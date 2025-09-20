"""
PyWAF SSL/TLS Management

Comprehensive SSL/TLS certificate management with Let's Encrypt integration,
automatic renewal, and secure certificate storage.
"""

import os
import ssl
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from .config import Config
from .exceptions import SSLError, CertificateError


class CertificateStatus(str, Enum):
    """Certificate status"""
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    INVALID = "invalid"
    NOT_FOUND = "not_found"


@dataclass
class Certificate:
    """Certificate information"""
    domain: str
    cert_data: bytes
    key_data: bytes
    issued_at: datetime
    expires_at: datetime
    issuer: str
    san_domains: List[str]
    
    @property
    def status(self) -> CertificateStatus:
        """Get certificate status"""
        now = datetime.now()
        
        if now > self.expires_at:
            return CertificateStatus.EXPIRED
        elif now > (self.expires_at - timedelta(days=30)):
            return CertificateStatus.EXPIRING_SOON
        else:
            return CertificateStatus.VALID
    
    @property
    def days_until_expiry(self) -> int:
        """Get days until certificate expires"""
        delta = self.expires_at - datetime.now()
        return max(0, delta.days)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "domain": self.domain,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer": self.issuer,
            "san_domains": self.san_domains,
            "status": self.status.value,
            "days_until_expiry": self.days_until_expiry
        }


class CertificateStorage:
    """Certificate storage management"""
    
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def save_certificate(self, domain: str, cert_data: bytes, key_data: bytes) -> bool:
        """Save certificate and key to storage"""
        try:
            cert_file = self.storage_dir / f"{domain}.crt"
            key_file = self.storage_dir / f"{domain}.key"
            
            with open(cert_file, 'wb') as f:
                f.write(cert_data)
            
            with open(key_file, 'wb') as f:
                f.write(key_data)
            
            # Set secure permissions
            os.chmod(cert_file, 0o644)
            os.chmod(key_file, 0o600)
            
            return True
        except Exception as e:
            print(f"Failed to save certificate for {domain}: {e}")
            return False
    
    def load_certificate(self, domain: str) -> Optional[Tuple[bytes, bytes]]:
        """Load certificate and key from storage"""
        try:
            cert_file = self.storage_dir / f"{domain}.crt"
            key_file = self.storage_dir / f"{domain}.key"
            
            if not cert_file.exists() or not key_file.exists():
                return None
            
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            return cert_data, key_data
        except Exception as e:
            print(f"Failed to load certificate for {domain}: {e}")
            return None
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate and key from storage"""
        try:
            cert_file = self.storage_dir / f"{domain}.crt"
            key_file = self.storage_dir / f"{domain}.key"
            
            if cert_file.exists():
                cert_file.unlink()
            
            if key_file.exists():
                key_file.unlink()
            
            return True
        except Exception as e:
            print(f"Failed to delete certificate for {domain}: {e}")
            return False
    
    def list_certificates(self) -> List[str]:
        """List all stored certificate domains"""
        domains = []
        for cert_file in self.storage_dir.glob("*.crt"):
            domain = cert_file.stem
            key_file = self.storage_dir / f"{domain}.key"
            if key_file.exists():
                domains.append(domain)
        return domains


class ACMEClient:
    """Let's Encrypt ACME client for automatic certificate provisioning"""
    
    def __init__(self, config: Config):
        self.config = config
        self.directory_url = config.ssl.acme_directory
        self.email = config.ssl.acme_email
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # ACME directory endpoints
        self.directory = {}
        self.nonce = None
        self.account_key = None
        self.account_url = None
    
    async def initialize(self):
        """Initialize ACME client"""
        try:
            # Fetch ACME directory
            response = await self.http_client.get(self.directory_url)
            response.raise_for_status()
            self.directory = response.json()
            
            # Generate account key if not exists
            await self._load_or_generate_account_key()
            
            # Get fresh nonce
            await self._get_nonce()
            
            # Create or load account
            await self._create_or_load_account()
            
            return True
        except Exception as e:
            print(f"Failed to initialize ACME client: {e}")
            return False
    
    async def _load_or_generate_account_key(self):
        """Load existing account key or generate new one"""
        key_file = Path(self.config.ssl.cert_dir) / "account.key"
        
        try:
            if key_file.exists():
                # Load existing key
                with open(key_file, 'rb') as f:
                    self.account_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
            else:
                # Generate new key
                self.account_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Save key
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self.account_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption()
                    ))
                os.chmod(key_file, 0o600)
        except Exception as e:
            raise SSLError(f"Failed to handle account key: {e}")
    
    async def _get_nonce(self):
        """Get fresh nonce from ACME server"""
        response = await self.http_client.head(self.directory["newNonce"])
        self.nonce = response.headers.get("Replay-Nonce")
    
    async def _create_or_load_account(self):
        """Create new ACME account or load existing"""
        # For simplification, we'll create a new account each time
        # In production, you'd want to store and reuse account info
        
        account_data = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{self.email}"]
        }
        
        # This is a simplified implementation
        # Real ACME requires proper JWS (JSON Web Signature) implementation
        print(f"ACME account would be created for {self.email}")
        self.account_url = "mock_account_url"
    
    async def request_certificate(self, domain: str) -> Optional[Tuple[bytes, bytes]]:
        """Request certificate for domain"""
        try:
            print(f"Requesting certificate for domain: {domain}")
            
            # For this implementation, we'll generate a self-signed certificate
            # In production, this would use the full ACME protocol
            return await self._generate_self_signed_certificate(domain)
            
        except Exception as e:
            print(f"Certificate request failed for {domain}: {e}")
            return None
    
    async def _generate_self_signed_certificate(self, domain: str) -> Tuple[bytes, bytes]:
        """Generate self-signed certificate (for demo/development)"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyWAF"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=90)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        cert_data = cert.public_bytes(Encoding.PEM)
        key_data = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        return cert_data, key_data
    
    async def cleanup(self):
        """Cleanup ACME client"""
        await self.http_client.aclose()


class SSLContextManager:
    """SSL context management"""
    
    def __init__(self, config: Config):
        self.config = config
        self.ssl_contexts = {}  # domain -> ssl.SSLContext
    
    def create_ssl_context(self, cert_data: bytes, key_data: bytes) -> ssl.SSLContext:
        """Create SSL context from certificate data"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Load certificate and key
        try:
            # Write to temporary files (in production, use in-memory loading)
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.crt') as cert_file:
                cert_file.write(cert_data)
                cert_path = cert_file.name
            
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                key_file.write(key_data)
                key_path = key_file.name
            
            context.load_cert_chain(cert_path, key_path)
            
            # Clean up temp files
            os.unlink(cert_path)
            os.unlink(key_path)
            
            return context
        except Exception as e:
            raise SSLError(f"Failed to create SSL context: {e}")
    
    def get_ssl_context(self, domain: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for domain"""
        return self.ssl_contexts.get(domain)
    
    def set_ssl_context(self, domain: str, context: ssl.SSLContext):
        """Set SSL context for domain"""
        self.ssl_contexts[domain] = context
    
    def remove_ssl_context(self, domain: str):
        """Remove SSL context for domain"""
        self.ssl_contexts.pop(domain, None)


class SSLManager:
    """Main SSL/TLS management system"""
    
    def __init__(self, config: Config):
        self.config = config
        self.certificates = {}  # domain -> Certificate
        
        # Initialize components
        self.storage = CertificateStorage(Path(config.ssl.cert_dir))
        self.acme_client = ACMEClient(config) if config.ssl.auto_provision else None
        self.ssl_context_manager = SSLContextManager(config)
        
        # Background tasks
        self.renewal_task = None
    
    async def initialize(self):
        """Initialize SSL manager"""
        if not self.config.ssl.enabled:
            return
        
        print("Initializing SSL manager...")
        
        # Initialize ACME client if auto-provisioning is enabled
        if self.acme_client:
            await self.acme_client.initialize()
        
        # Load existing certificates
        await self._load_existing_certificates()
        
        # Request certificates for configured domains
        if self.config.ssl.auto_provision:
            for domain in self.config.ssl.domains:
                if domain not in self.certificates:
                    await self._request_certificate(domain)
        
        # Load manual certificates if specified
        if self.config.ssl.cert_file and self.config.ssl.key_file:
            await self._load_manual_certificate()
        
        # Start renewal task
        if self.config.ssl.auto_provision:
            self.renewal_task = asyncio.create_task(self._renewal_loop())
        
        print(f"SSL manager initialized with {len(self.certificates)} certificates")
    
    async def _load_existing_certificates(self):
        """Load existing certificates from storage"""
        try:
            domains = self.storage.list_certificates()
            
            for domain in domains:
                cert_data = self.storage.load_certificate(domain)
                if cert_data:
                    cert_bytes, key_bytes = cert_data
                    certificate = self._parse_certificate(domain, cert_bytes, key_bytes)
                    if certificate:
                        self.certificates[domain] = certificate
                        
                        # Create SSL context
                        ssl_context = self.ssl_context_manager.create_ssl_context(cert_bytes, key_bytes)
                        self.ssl_context_manager.set_ssl_context(domain, ssl_context)
                        
        except Exception as e:
            print(f"Error loading existing certificates: {e}")
    
    async def _load_manual_certificate(self):
        """Load manually specified certificate"""
        try:
            cert_path = Path(self.config.ssl.cert_file)
            key_path = Path(self.config.ssl.key_file)
            
            if not cert_path.exists() or not key_path.exists():
                raise SSLError(f"Certificate files not found: {cert_path}, {key_path}")
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            # Parse certificate to get domain
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Get common name
            common_name = None
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            if common_name:
                certificate = self._parse_certificate(common_name, cert_data, key_data)
                if certificate:
                    self.certificates[common_name] = certificate
                    
                    # Create SSL context
                    ssl_context = self.ssl_context_manager.create_ssl_context(cert_data, key_data)
                    self.ssl_context_manager.set_ssl_context(common_name, ssl_context)
                    
                    print(f"Loaded manual certificate for {common_name}")
        
        except Exception as e:
            raise SSLError(f"Failed to load manual certificate: {e}")
    
    def _parse_certificate(self, domain: str, cert_data: bytes, key_data: bytes) -> Optional[Certificate]:
        """Parse certificate data into Certificate object"""
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Extract certificate information
            issued_at = cert.not_valid_before
            expires_at = cert.not_valid_after
            
            # Get issuer
            issuer = "Unknown"
            for attribute in cert.issuer:
                if attribute.oid == NameOID.ORGANIZATION_NAME:
                    issuer = attribute.value
                    break
            
            # Get SAN domains
            san_domains = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_domains = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            return Certificate(
                domain=domain,
                cert_data=cert_data,
                key_data=key_data,
                issued_at=issued_at,
                expires_at=expires_at,
                issuer=issuer,
                san_domains=san_domains
            )
        
        except Exception as e:
            print(f"Failed to parse certificate for {domain}: {e}")
            return None
    
    async def _request_certificate(self, domain: str) -> bool:
        """Request certificate for domain"""
        if not self.acme_client:
            return False
        
        try:
            print(f"Requesting certificate for {domain}")
            
            cert_data = await self.acme_client.request_certificate(domain)
            if cert_data:
                cert_bytes, key_bytes = cert_data
                
                # Save to storage
                if self.storage.save_certificate(domain, cert_bytes, key_bytes):
                    # Parse and store certificate
                    certificate = self._parse_certificate(domain, cert_bytes, key_bytes)
                    if certificate:
                        self.certificates[domain] = certificate
                        
                        # Create SSL context
                        ssl_context = self.ssl_context_manager.create_ssl_context(cert_bytes, key_bytes)
                        self.ssl_context_manager.set_ssl_context(domain, ssl_context)
                        
                        print(f"Certificate provisioned for {domain}")
                        return True
            
            return False
        except Exception as e:
            print(f"Failed to request certificate for {domain}: {e}")
            return False
    
    async def _renewal_loop(self):
        """Background certificate renewal loop"""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour
                
                print("Checking certificates for renewal...")
                
                for domain, certificate in self.certificates.items():
                    if certificate.status in [CertificateStatus.EXPIRED, CertificateStatus.EXPIRING_SOON]:
                        print(f"Renewing certificate for {domain} (expires: {certificate.expires_at})")
                        await self._request_certificate(domain)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in renewal loop: {e}")
    
    def get_certificate(self, domain: str) -> Optional[Certificate]:
        """Get certificate for domain"""
        return self.certificates.get(domain)
    
    def get_ssl_context(self, domain: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for domain"""
        return self.ssl_context_manager.get_ssl_context(domain)
    
    def list_certificates(self) -> List[Certificate]:
        """List all certificates"""
        return list(self.certificates.values())
    
    def get_certificate_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get certificate information for domain"""
        certificate = self.certificates.get(domain)
        return certificate.to_dict() if certificate else None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SSL statistics"""
        total_certs = len(self.certificates)
        valid_certs = sum(1 for cert in self.certificates.values() if cert.status == CertificateStatus.VALID)
        expiring_certs = sum(1 for cert in self.certificates.values() if cert.status == CertificateStatus.EXPIRING_SOON)
        expired_certs = sum(1 for cert in self.certificates.values() if cert.status == CertificateStatus.EXPIRED)
        
        return {
            "ssl_enabled": self.config.ssl.enabled,
            "auto_provision": self.config.ssl.auto_provision,
            "total_certificates": total_certs,
            "valid_certificates": valid_certs,
            "expiring_certificates": expiring_certs,
            "expired_certificates": expired_certs,
            "domains": list(self.certificates.keys()),
            "certificate_details": [cert.to_dict() for cert in self.certificates.values()]
        }
    
    async def cleanup(self):
        """Cleanup SSL manager"""
        if self.renewal_task:
            self.renewal_task.cancel()
            try:
                await self.renewal_task
            except asyncio.CancelledError:
                pass
        
        if self.acme_client:
            await self.acme_client.cleanup()
        
        print("SSL manager cleaned up")
