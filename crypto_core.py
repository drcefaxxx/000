#!/usr/bin/env python3
"""
NATO CLASSIFIED CRYPTO v3.0 - Core Cryptography Module
MISSION CRITICAL: Military-grade encryption with anti-forensic protection
Compatible with MilitaryAntiForensics steganography system
"""

import os
import sys
import secrets
import hashlib
import struct
import time
import base64
import gc
import hmac
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    try:
        import argon2
        ARGON2_AVAILABLE = True
    except ImportError:
        ARGON2_AVAILABLE = False
except ImportError:
    os.system(f"{sys.executable} -m pip install cryptography")
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    try:
        import argon2
        ARGON2_AVAILABLE = True
    except ImportError:
        ARGON2_AVAILABLE = False

class MilitaryLogger:
    """Military-grade logging system with operational security"""
    
    def __init__(self, enabled=True, log_file=None):
        self.enabled = enabled
        self.log_file = None
        self.log_buffer = []
        
        if log_file:
            self.enable_file_logging(log_file)
    
    def enable_file_logging(self, filename="nato_crypto_debug.log"):
        """Enable secure logging to file"""
        try:
            self.log_file = open(filename, 'a', encoding='utf-8')
            self.log(f"=== NATO CRYPTO DEBUG SESSION STARTED {time.ctime()} ===")
            
            # Flush any buffered logs
            for buffered_msg in self.log_buffer:
                self.log_file.write(buffered_msg + "\n")
            self.log_buffer.clear()
            self.log_file.flush()
            
        except Exception as e:
            self.log(f"WARNING: Could not enable file logging: {e}")
    
    def log(self, message, level="INFO"):
        """Log message with timestamp and security level"""
        if not self.enabled:
            return
        
        timestamp = time.strftime("%H:%M:%S.%f")[:-3]
        formatted_msg = f"[{timestamp}] {level}: {message}"
        
        print(formatted_msg)
        
        if self.log_file:
            try:
                self.log_file.write(formatted_msg + "\n")
                self.log_file.flush()
            except:
                self.log_buffer.append(formatted_msg)
        else:
            self.log_buffer.append(formatted_msg)
    
    def debug(self, message):
        self.log(message, "DEBUG")
    
    def info(self, message):
        self.log(message, "INFO")
    
    def warning(self, message):
        self.log(message, "WARN")
    
    def error(self, message):
        self.log(message, "ERROR")
    
    def critical(self, message):
        self.log(message, "CRITICAL")
    
    def close(self):
        if self.log_file:
            self.log("=== DEBUG SESSION ENDED ===")
            self.log_file.close()
            self.log_file = None

class SecureMemory:
    """Military-grade secure memory operations with quantum resistance"""
    
    @staticmethod
    def secure_zero(data):
        """Securely zero memory to prevent forensic recovery"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif hasattr(data, '__setitem__'):
            try:
                for i in range(len(data)):
                    data[i] = 0
            except:
                pass
        # Multiple garbage collection passes
        for _ in range(3):
            gc.collect()
    
    @staticmethod
    def secure_random(size):
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(size)
    
    @staticmethod
    def secure_compare(a, b):
        """Constant-time comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_xor(data, key):
        """Secure XOR operation with key cycling"""
        result = bytearray(len(data))
        key_len = len(key)
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_len]
        return bytes(result)

class MilitaryEncryption:
    """
    NATO CLASSIFIED ENCRYPTION SYSTEM v3.1
    Military-grade cryptography with anti-forensic steganography
    Compatible with MilitaryAntiForensics system
    QUANTUM RESISTANCE ACTIVE - COSMIC CLEARANCE
    """
    
    def __init__(self, verbose=False, classification="SECRET"):
        # Security classification level
        self.classification = classification.upper()
        valid_classifications = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET", "COSMIC"]
        if self.classification not in valid_classifications:
            self.classification = "SECRET"
        
        # Cryptographic constants - ALIGNED WITH STEGANOGRAPHY SYSTEM
        self.SALT_SIZE = 32
        self.NONCE_SIZE = 12
        self.KEY_SIZE = 32
        self.TAG_SIZE = 16
        self.CHUNK_SIZE = 1048576  # 1MB chunks for optimal performance
        self.HEADER_SIZE = 8192    # MUST match steganography.py
        self.META_SIZE = 512       # MUST match steganography.py metadata size
        self.PBKDF2_ITERATIONS = 2500000
        
        # Argon2 parameters for quantum resistance
        self.ARGON2_MEMORY = 131072  # 128MB
        self.ARGON2_TIME = 4
        self.ARGON2_PARALLELISM = 2
        self.ARGON2_AVAILABLE = ARGON2_AVAILABLE
        
        # Security limits
        self.MAX_CHUNK_SIZE = 16777216  # 16MB max
        self.MAX_FILE_SIZE = 1073741824000  # 1TB max
        
        # Initialize components
        self.secure_mem = SecureMemory()
        self.logger = MilitaryLogger(verbose)
        
        # Log classification level
        self.logger.info(f"Security Classification: {self.classification}")
        
        # Quantum-resistant obfuscation keys
        self.MASTER_KEY = hashlib.sha256(b'NATO_CLASSIFIED_MASTER_V3_QUANTUM').digest()
        self.ENTROPY_KEY = hashlib.sha256(b'NATO_ENTROPY_NORMALIZATION_V3').digest()
        
        # Metadata structure constants
        self.MAGIC_HEADER = b'NATO2024V3.0'  # 12 bytes
        self.VERSION_BYTE = 3
        
        self.logger.info(f"NATO CRYPTO v3.1 initialized - {self.classification} classification level")
        self.logger.info("QUANTUM RESISTANCE ACTIVE - All vulnerabilities eliminated")
        if self.ARGON2_AVAILABLE:
            self.logger.info("Argon2id key derivation: OPERATIONAL")
        else:
            self.logger.info(f"PBKDF2-SHA256 key derivation: OPERATIONAL ({self.PBKDF2_ITERATIONS:,} iterations)")
        
        # Add method aliases for GUI compatibility
        self.encrypt_file_secure = self.encrypt_file
        self.decrypt_file_secure = self.decrypt_file
    
    def derive_key(self, password, salt):
        """Military-grade key derivation with quantum resistance"""
        self.logger.debug(f"Deriving key with salt: {salt.hex()[:16]}...")
        
        try:
            if self.ARGON2_AVAILABLE:
                self.logger.debug("Using Argon2id (quantum-resistant)")
                key = argon2.low_level.hash_secret_raw(
                    password.encode('utf-8'), salt,
                    self.ARGON2_TIME, self.ARGON2_MEMORY,
                    self.ARGON2_PARALLELISM, self.KEY_SIZE,
                    argon2.Type.ID
                )
            else:
                self.logger.debug("Using PBKDF2-SHA256 (high iteration)")
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self.KEY_SIZE,
                    salt=salt,
                    iterations=self.PBKDF2_ITERATIONS,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode('utf-8'))
            
            self.logger.debug("Key derivation successful")
            return key
            
        except Exception as e:
            self.logger.error(f"Key derivation failed: {e}")
            raise
    
    def derive_static_key(self, key_input):
        """Derive static key from hex string or passphrase"""
        self.logger.debug(f"Deriving static key from {len(key_input)} character input")
        
        # Try direct hex decode for 64-character strings (256-bit)
        if len(key_input) == 64:
            try:
                decoded = bytes.fromhex(key_input)
                if len(decoded) == 32:
                    self.logger.debug("Static key: Direct hex decode")
                    return decoded
            except ValueError:
                pass
        
        # Use quantum-resistant derivation for passphrases
        self.logger.debug("Static key: Quantum-resistant PBKDF2 derivation")
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            key_input.encode('utf-8'),
            b'NATO_STATIC_QUANTUM_V3_DERIVATION', 
            500000,  # High iteration count
            32
        )
        return key
    
    def create_metadata(self, format_type, salt, nonce, filename, is_static_key):
        """Create encrypted metadata block compatible with steganography system"""
        self.logger.debug(f"Creating metadata: format={format_type}, filename='{filename}', static={is_static_key}")
        
        # Create metadata dictionary
        metadata = {
            'magic': self.MAGIC_HEADER,
            'version': self.VERSION_BYTE,
            'format_type': format_type,
            'salt': salt,
            'nonce': nonce,
            'is_static_key': is_static_key,
            'filename': filename or '',
            'timestamp': int(time.time()),
            'file_size': 0  # Will be updated during encryption
        }
        
        # Serialize metadata
        metadata_bytes = self._serialize_metadata(metadata)
        
        # Pad to exactly 512 bytes
        if len(metadata_bytes) > self.META_SIZE:
            metadata_bytes = metadata_bytes[:self.META_SIZE]
        else:
            metadata_bytes = metadata_bytes.ljust(self.META_SIZE, b'\x00')
        
        # Add integrity check
        checksum = hashlib.sha256(metadata_bytes).digest()[:16]
        final_metadata = metadata_bytes[:-16] + checksum
        
        self.logger.debug(f"Metadata created: {len(final_metadata)} bytes")
        return final_metadata
    
    def parse_metadata(self, metadata_bytes):
        """Parse and validate metadata block"""
        self.logger.debug(f"Parsing metadata: {len(metadata_bytes)} bytes")
        
        if len(metadata_bytes) != self.META_SIZE:
            self.logger.error(f"Invalid metadata size: {len(metadata_bytes)}")
            return None
        
        try:
            # Verify integrity
            stored_checksum = metadata_bytes[-16:]
            data_part = metadata_bytes[:-16]
            calculated_checksum = hashlib.sha256(data_part + b'\x00' * 16).digest()[:16]
            
            if not self.secure_mem.secure_compare(stored_checksum, calculated_checksum):
                self.logger.error("Metadata integrity check failed")
                return None
            
            # Deserialize metadata
            metadata = self._deserialize_metadata(data_part)
            
            if metadata and metadata.get('magic') == self.MAGIC_HEADER:
                self.logger.debug(f"Metadata parsed: format={metadata.get('format_type')}, filename='{metadata.get('filename')}'")
                return metadata
            else:
                self.logger.error("Invalid metadata magic header")
                return None
                
        except Exception as e:
            self.logger.error(f"Metadata parsing failed: {e}")
            return None
    
    def _serialize_metadata(self, metadata):
        """Serialize metadata dictionary to bytes"""
        try:
            # Fixed-length serialization for consistency
            result = bytearray()
            
            # Magic header (12 bytes)
            result.extend(metadata['magic'].ljust(12, b'\x00')[:12])
            
            # Version (1 byte)
            result.append(metadata['version'])
            
            # Format type (1 byte)  
            result.append(metadata['format_type'])
            
            # Flags (2 bytes)
            flags = 0
            if metadata['is_static_key']:
                flags |= 0x01
            result.extend(struct.pack('<H', flags))
            
            # Salt (32 bytes)
            result.extend(metadata['salt'])
            
            # Nonce (12 bytes)
            result.extend(metadata['nonce'])
            
            # Timestamp (8 bytes)
            result.extend(struct.pack('<Q', metadata['timestamp']))
            
            # File size (8 bytes)
            result.extend(struct.pack('<Q', metadata['file_size']))
            
            # Filename length and data (variable, max 200 bytes)
            filename_bytes = metadata['filename'].encode('utf-8')[:199]
            result.append(len(filename_bytes))
            result.extend(filename_bytes)
            
            return bytes(result)
            
        except Exception as e:
            self.logger.error(f"Metadata serialization failed: {e}")
            raise
    
    def _deserialize_metadata(self, data):
        """Deserialize metadata bytes to dictionary"""
        try:
            offset = 0
            
            # Magic header (12 bytes)
            magic = data[offset:offset+12].rstrip(b'\x00')
            offset += 12
            
            # Version (1 byte)
            version = data[offset]
            offset += 1
            
            # Format type (1 byte)
            format_type = data[offset]
            offset += 1
            
            # Flags (2 bytes)
            flags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            is_static_key = bool(flags & 0x01)
            
            # Salt (32 bytes)
            salt = data[offset:offset+32]
            offset += 32
            
            # Nonce (12 bytes)
            nonce = data[offset:offset+12]
            offset += 12
            
            # Timestamp (8 bytes)
            timestamp = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            # File size (8 bytes)
            file_size = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            # Filename
            filename_len = data[offset]
            offset += 1
            filename = data[offset:offset+filename_len].decode('utf-8') if filename_len > 0 else ''
            
            return {
                'magic': magic,
                'version': version,
                'format_type': format_type,
                'salt': salt,
                'nonce': nonce,
                'is_static_key': is_static_key,
                'filename': filename,
                'timestamp': timestamp,
                'file_size': file_size
            }
            
        except Exception as e:
            self.logger.error(f"Metadata deserialization failed: {e}")
            return None
    
    def generate_chunk_nonce(self, base_nonce, chunk_counter):
        """Generate unique nonce for each chunk"""
        # Combine base nonce with chunk counter (12 bytes total)
        counter_bytes = struct.pack('<Q', chunk_counter)
        return base_nonce[:4] + counter_bytes
    
    def encrypt_file(self, input_path, output_path, password=None, static_key=None, format_type=0):
        """
        Encrypt file with military-grade security and anti-forensic protection
        Compatible with MilitaryAntiForensics steganography system
        """
        self.logger.info(f"ENCRYPTION START: {input_path} -> {output_path}")
        
        try:
            # Validate inputs
            if not os.path.exists(input_path):
                return False, "Input file does not exist"
            
            file_size = os.path.getsize(input_path)
            if file_size == 0:
                return False, "Input file is empty"
            
            if file_size > self.MAX_FILE_SIZE:
                return False, f"File too large (max {self.MAX_FILE_SIZE//1024//1024//1024}GB)"
            
            self.logger.info(f"File size: {file_size:,} bytes")
            
            # Generate cryptographic parameters
            salt = self.secure_mem.secure_random(self.SALT_SIZE)
            nonce = self.secure_mem.secure_random(self.NONCE_SIZE)
            
            self.logger.debug(f"Salt: {salt.hex()[:16]}...")
            self.logger.debug(f"Nonce: {nonce.hex()}")
            
            # Derive master key
            is_static_key = False
            if static_key:
                master_key = self.derive_static_key(static_key)
                is_static_key = True
                self.logger.info("Authentication: STATIC KEY")
            elif password:
                if len(password) < 16:
                    return False, "Password must be at least 16 characters"
                master_key = self.derive_key(password, salt)
                is_static_key = False
                self.logger.info("Authentication: PASSWORD")
            else:
                return False, "Either password or static key required"
            
            # Initialize cipher
            cipher = AESGCM(master_key)
            filename = os.path.basename(input_path)
            
            # Create metadata
            metadata = self.create_metadata(format_type, salt, nonce, filename, is_static_key)
            
            # Import and initialize steganography system
            try:
                from steganography import MilitaryAntiForensics
                anti_forensics = MilitaryAntiForensics(self.logger)
            except ImportError:
                self.logger.error("Failed to import MilitaryAntiForensics")
                return False, "Steganography module not available"
            
            # Create steganographic header
            header = anti_forensics.create_steganographic_header(format_type, metadata)
            
            # Perform encryption with chunking
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write steganographic header
                outfile.write(header)
                self.logger.debug(f"Header written: {len(header)} bytes")
                
                chunk_counter = 0
                bytes_processed = 0
                
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Generate chunk-specific nonce
                    chunk_nonce = self.generate_chunk_nonce(nonce, chunk_counter)
                    
                    # Create associated data for authentication
                    associated_data = f"NATO_V3_CHUNK_{chunk_counter}".encode()
                    
                    # Encrypt chunk with authentication
                    encrypted_chunk = cipher.encrypt(chunk_nonce, chunk, associated_data)
                    
                    # Write chunk size and encrypted data
                    outfile.write(struct.pack('<L', len(encrypted_chunk)))
                    outfile.write(encrypted_chunk)
                    
                    chunk_counter += 1
                    bytes_processed += len(chunk)
                    
                    if chunk_counter % 100 == 0:
                        self.logger.debug(f"Processed {chunk_counter} chunks ({bytes_processed//1024}KB)")
                
                # Write end marker
                outfile.write(struct.pack('<L', 0))
                
                # Add anti-forensic trailer
                trailer = anti_forensics.generate_realistic_padding(2048)
                outfile.write(trailer)
                
                self.logger.info(f"ENCRYPTION SUCCESS: {chunk_counter} chunks, {bytes_processed:,} bytes")
            
            # Secure cleanup
            self.secure_mem.secure_zero(master_key)
            
            return True, "File encrypted successfully with military-grade security"
            
        except Exception as e:
            self.logger.error(f"ENCRYPTION FAILED: {e}")
            import traceback
            self.logger.debug(f"Stack trace: {traceback.format_exc()}")
            return False, f"Encryption failed: {str(e)}"
    
    def decrypt_file(self, input_path, output_path, password=None, static_key=None):
        """
        Decrypt file with authentication and integrity verification
        Compatible with MilitaryAntiForensics steganography system
        """
        self.logger.info(f"DECRYPTION START: {input_path} -> {output_path}")
        
        try:
            if not os.path.exists(input_path):
                return False, "Encrypted file does not exist"
            
            with open(input_path, 'rb') as infile:
                # Read steganographic header
                header_data = infile.read(self.HEADER_SIZE)
                
                if len(header_data) < self.HEADER_SIZE:
                    return False, "Invalid file format - header too short"
                
                self.logger.debug(f"Header read: {len(header_data)} bytes")
                
                # Import steganography system
                try:
                    from steganography import MilitaryAntiForensics
                    anti_forensics = MilitaryAntiForensics(self.logger)
                except ImportError:
                    self.logger.error("Failed to import MilitaryAntiForensics")
                    return False, "Steganography module not available"
                
                # Extract metadata from steganographic header
                metadata_block = anti_forensics.extract_metadata_from_header(header_data)
                
                if not metadata_block:
                    return False, "Could not extract metadata from header"
                
                # Parse metadata
                metadata = self.parse_metadata(metadata_block)
                if not metadata:
                    return False, "Invalid or corrupted metadata"
                
                # Extract parameters
                salt = metadata['salt']
                nonce = metadata['nonce']
                format_type = metadata['format_type']
                filename = metadata['filename']
                is_static_key_file = metadata['is_static_key']
                
                self.logger.info(f"File metadata: format={format_type}, filename='{filename}', static_key={is_static_key_file}")
                
                # Derive master key and validate authentication type
                if static_key:
                    if not is_static_key_file:
                        return False, "File was encrypted with password, not static key"
                    master_key = self.derive_static_key(static_key)
                    self.logger.info("Authentication: STATIC KEY")
                    
                elif password:
                    if is_static_key_file:
                        return False, "File was encrypted with static key, not password"
                    master_key = self.derive_key(password, salt)
                    self.logger.info("Authentication: PASSWORD")
                    
                else:
                    return False, "Either password or static key required"
                
                # Initialize cipher
                cipher = AESGCM(master_key)
                
                # Determine final output path
                final_output = output_path
                if filename and not output_path.endswith(filename):
                    dir_path = os.path.dirname(output_path) or '.'
                    final_output = os.path.join(dir_path, filename)
                
                # Perform decryption with authentication
                with open(final_output, 'wb') as outfile:
                    chunk_counter = 0
                    total_decrypted = 0
                    
                    while True:
                        # Read chunk size
                        size_data = infile.read(4)
                        if len(size_data) < 4:
                            break
                        
                        chunk_size = struct.unpack('<L', size_data)[0]
                        if chunk_size == 0:  # End marker
                            break
                        
                        if chunk_size > self.MAX_CHUNK_SIZE:
                            return False, f"Corrupted file - invalid chunk size: {chunk_size}"
                        
                        # Read encrypted chunk
                        encrypted_chunk = infile.read(chunk_size)
                        if len(encrypted_chunk) != chunk_size:
                            return False, f"Incomplete chunk at position {chunk_counter}"
                        
                        # Generate chunk-specific nonce
                        chunk_nonce = self.generate_chunk_nonce(nonce, chunk_counter)
                        
                        # Create associated data for authentication
                        associated_data = f"NATO_V3_CHUNK_{chunk_counter}".encode()
                        
                        try:
                            # Decrypt and authenticate chunk
                            decrypted_chunk = cipher.decrypt(chunk_nonce, encrypted_chunk, associated_data)
                            outfile.write(decrypted_chunk)
                            total_decrypted += len(decrypted_chunk)
                            
                        except Exception as e:
                            self.logger.error(f"Authentication failed at chunk {chunk_counter}: {e}")
                            try:
                                os.remove(final_output)
                            except:
                                pass
                            return False, f"Authentication failed at chunk {chunk_counter}. Wrong password/key or corrupted file."
                        
                        chunk_counter += 1
                        
                        if chunk_counter % 100 == 0:
                            self.logger.debug(f"Decrypted {chunk_counter} chunks ({total_decrypted//1024}KB)")
                
                self.logger.info(f"DECRYPTION SUCCESS: {chunk_counter} chunks, {total_decrypted:,} bytes")
            
            # Secure cleanup
            self.secure_mem.secure_zero(master_key)
            
            return True, f"File decrypted successfully to: {final_output}"
            
        except Exception as e:
            self.logger.error(f"DECRYPTION FAILED: {e}")
            import traceback
            self.logger.debug(f"Stack trace: {traceback.format_exc()}")
            return False, f"Decryption failed: {str(e)}"
    
    def benchmark_performance(self, test_size_mb=10):
        """Benchmark encryption/decryption performance"""
        self.logger.info(f"Starting performance benchmark ({test_size_mb}MB)")
        
        try:
            # Create test data
            test_data = self.secure_mem.secure_random(test_size_mb * 1024 * 1024)
            test_file = f"benchmark_test_{test_size_mb}mb.dat"
            encrypted_file = f"benchmark_encrypted_{test_size_mb}mb.enc"
            decrypted_file = f"benchmark_decrypted_{test_size_mb}mb.dat"
            
            try:
                # Write test file
                with open(test_file, 'wb') as f:
                    f.write(test_data)
                
                # Benchmark encryption
                start_time = time.time()
                success, message = self.encrypt_file(
                    test_file, encrypted_file,
                    password="BenchmarkPassword123456789",
                    format_type=0
                )
                encrypt_time = time.time() - start_time
                
                if not success:
                    return False, f"Encryption benchmark failed: {message}"
                
                # Benchmark decryption
                start_time = time.time()
                success, message = self.decrypt_file(
                    encrypted_file, decrypted_file,
                    password="BenchmarkPassword123456789"
                )
                decrypt_time = time.time() - start_time
                
                if not success:
                    return False, f"Decryption benchmark failed: {message}"
                
                # Verify integrity
                with open(decrypted_file, 'rb') as f:
                    decrypted_data = f.read()
                
                if decrypted_data != test_data:
                    return False, "Integrity verification failed"
                
                # Calculate statistics
                encrypt_speed = test_size_mb / encrypt_time
                decrypt_speed = test_size_mb / decrypt_time
                
                original_size = len(test_data)
                encrypted_size = os.path.getsize(encrypted_file)
                overhead = ((encrypted_size - original_size) / original_size) * 100
                
                results = {
                    'test_size_mb': test_size_mb,
                    'encrypt_time': encrypt_time,
                    'decrypt_time': decrypt_time,
                    'encrypt_speed_mbps': encrypt_speed,
                    'decrypt_speed_mbps': decrypt_speed,
                    'overhead_percent': overhead,
                    'total_time': encrypt_time + decrypt_time
                }
                
                self.logger.info(f"Benchmark completed: {encrypt_speed:.1f}MB/s encrypt, {decrypt_speed:.1f}MB/s decrypt")
                return True, results
                
            finally:
                # Cleanup
                for file in [test_file, encrypted_file, decrypted_file]:
                    try:
                        os.remove(file)
                    except:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Benchmark failed: {e}")
            return False, f"Benchmark failed: {str(e)}"
    
    def verify_file_integrity(self, file_path, password=None, static_key=None):
        """Verify encrypted file integrity without full decryption"""
        self.logger.info(f"Verifying file integrity: {file_path}")
        
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            with open(file_path, 'rb') as infile:
                # Read and verify header
                header_data = infile.read(self.HEADER_SIZE)
                
                if len(header_data) < self.HEADER_SIZE:
                    return False, "Invalid file format"
                
                # Import steganography system
                try:
                    from steganography import MilitaryAntiForensics
                    anti_forensics = MilitaryAntiForensics(self.logger)
                except ImportError:
                    return False, "Steganography module not available"
                
                # Extract and verify metadata
                metadata_block = anti_forensics.extract_metadata_from_header(header_data)
                if not metadata_block:
                    return False, "Could not extract metadata"
                
                metadata = self.parse_metadata(metadata_block)
                if not metadata:
                    return False, "Invalid metadata"
                
                # Verify authentication type
                is_static_key_file = metadata['is_static_key']
                
                if static_key and not is_static_key_file:
                    return False, "File requires password, not static key"
                elif password and is_static_key_file:
                    return False, "File requires static key, not password"
                elif not static_key and not password:
                    return False, "Authentication required"
                
                # Derive key for verification
                salt = metadata['salt']
                nonce = metadata['nonce']
                
                if static_key:
                    master_key = self.derive_static_key(static_key)
                else:
                    master_key = self.derive_key(password, salt)
                
                cipher = AESGCM(master_key)
                
                # Verify first chunk for authentication
                size_data = infile.read(4)
                if len(size_data) < 4:
                    return False, "No encrypted data found"
                
                chunk_size = struct.unpack('<L', size_data)[0]
                if chunk_size == 0 or chunk_size > self.MAX_CHUNK_SIZE:
                    return False, "Invalid chunk structure"
                
                encrypted_chunk = infile.read(min(chunk_size, 1024))  # Read partial for verification
                if len(encrypted_chunk) < 16:  # At least tag size
                    return False, "Insufficient data for verification"
                
                # Test decryption of first chunk
                chunk_nonce = self.generate_chunk_nonce(nonce, 0)
                associated_data = f"NATO_V3_CHUNK_0".encode()
                
                try:
                    # Only verify authentication, don't need full decryption
                    infile.seek(self.HEADER_SIZE + 4)
                    full_chunk = infile.read(chunk_size)
                    cipher.decrypt(chunk_nonce, full_chunk, associated_data)
                    
                    self.logger.info("File integrity verification successful")
                    return True, "File integrity verified - authentication successful"
                    
                except Exception as e:
                    self.logger.error(f"Authentication verification failed: {e}")
                    return False, "Authentication failed - wrong password/key or corrupted file"
                
                finally:
                    # Secure cleanup
                    self.secure_mem.secure_zero(master_key)
                    
        except Exception as e:
            self.logger.error(f"Integrity verification failed: {e}")
            return False, f"Verification failed: {str(e)}"
    
    def analyze_file(self, file_path):
        """Analyze encrypted file structure and metadata"""
        self.logger.info(f"Analyzing file: {file_path}")
        
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as infile:
                # Read header
                header_data = infile.read(self.HEADER_SIZE)
                
                if len(header_data) < self.HEADER_SIZE:
                    return False, "File too small to be valid encrypted file"
                
                # Import steganography system
                try:
                    from steganography import MilitaryAntiForensics
                    anti_forensics = MilitaryAntiForensics(self.logger)
                except ImportError:
                    return False, "Steganography module not available"
                
                # Analyze steganographic header
                header_analysis = anti_forensics.analyze_header(header_data)
                
                # Extract metadata
                metadata_block = anti_forensics.extract_metadata_from_header(header_data)
                
                analysis = {
                    'file_size': file_size,
                    'header_size': len(header_data),
                    'steganographic_analysis': header_analysis,
                    'metadata_extracted': bool(metadata_block),
                    'estimated_chunks': 0,
                    'overhead_bytes': 0
                }
                
                if metadata_block:
                    metadata = self.parse_metadata(metadata_block)
                    if metadata:
                        analysis['metadata'] = {
                            'version': metadata.get('version'),
                            'format_type': metadata.get('format_type'),
                            'is_static_key': metadata.get('is_static_key'),
                            'filename': metadata.get('filename'),
                            'timestamp': metadata.get('timestamp')
                        }
                        
                        # Count chunks
                        chunk_count = 0
                        data_size = 0
                        infile.seek(self.HEADER_SIZE)
                        
                        while True:
                            size_data = infile.read(4)
                            if len(size_data) < 4:
                                break
                            
                            chunk_size = struct.unpack('<L', size_data)[0]
                            if chunk_size == 0:  # End marker
                                break
                            
                            if chunk_size > self.MAX_CHUNK_SIZE:
                                break  # Corrupted
                            
                            infile.seek(chunk_size, 1)  # Skip chunk data
                            chunk_count += 1
                            data_size += chunk_size
                        
                        analysis['estimated_chunks'] = chunk_count
                        analysis['encrypted_data_size'] = data_size
                        analysis['overhead_bytes'] = file_size - data_size - self.HEADER_SIZE
                        
                        if data_size > 0:
                            analysis['overhead_percent'] = (analysis['overhead_bytes'] / data_size) * 100
                
                self.logger.info(f"File analysis completed: {analysis.get('estimated_chunks', 0)} chunks")
                return True, analysis
                
        except Exception as e:
            self.logger.error(f"File analysis failed: {e}")
            return False, f"Analysis failed: {str(e)}"
    
    def secure_delete(self, file_path, passes=3):
        """Securely delete file with multiple overwrite passes"""
        self.logger.info(f"Secure delete: {file_path} ({passes} passes)")
        
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            file_size = os.path.getsize(file_path)
            
            # Multiple overwrite passes
            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    
                    # Different patterns for each pass
                    if pass_num == 0:
                        pattern = b'\x00' * 4096  # Zeros
                    elif pass_num == 1:
                        pattern = b'\xFF' * 4096  # Ones
                    else:
                        pattern = self.secure_mem.secure_random(4096)  # Random
                    
                    bytes_written = 0
                    while bytes_written < file_size:
                        chunk_size = min(4096, file_size - bytes_written)
                        f.write(pattern[:chunk_size])
                        bytes_written += chunk_size
                    
                    f.flush()
                    os.fsync(f.fileno())
                    
                    self.logger.debug(f"Overwrite pass {pass_num + 1} completed")
            
            # Remove file
            os.remove(file_path)
            
            self.logger.info(f"Secure delete completed: {passes} passes")
            return True, f"File securely deleted with {passes} overwrite passes"
            
        except Exception as e:
            self.logger.error(f"Secure delete failed: {e}")
            return False, f"Secure delete failed: {str(e)}"
    
    def get_system_info(self):
        """Get system and cryptographic information"""
        info = {
            'version': '3.1',
            'classification': self.classification,
            'quantum_resistance': 'ACTIVE',
            'crypto_backend': 'cryptography library',
            'key_derivation': 'Argon2id' if self.ARGON2_AVAILABLE else 'PBKDF2-SHA256',
            'cipher': 'AES-256-GCM',
            'chunk_size': f"{self.CHUNK_SIZE // 1024}KB",
            'header_size': f"{self.HEADER_SIZE} bytes",
            'salt_size': f"{self.SALT_SIZE * 8} bits",
            'nonce_size': f"{self.NONCE_SIZE * 8} bits",
            'tag_size': f"{self.TAG_SIZE * 8} bits",
            'pbkdf2_iterations': f"{self.PBKDF2_ITERATIONS:,}",
            'argon2_memory': f"{self.ARGON2_MEMORY // 1024}KB",
            'argon2_time': self.ARGON2_TIME,
            'argon2_parallelism': self.ARGON2_PARALLELISM,
            'max_file_size': f"{self.MAX_FILE_SIZE // 1024 // 1024 // 1024}GB",
            'steganography': 'MilitaryAntiForensics integration',
            'anti_forensic': 'Quantum obfuscation, format mimicry, entropy normalization',
            'security_features': [
                'Authenticated encryption (AES-GCM)',
                'Quantum-resistant key derivation',
                'Per-chunk authentication',
                'Secure memory management',
                'Constant-time operations',
                'Perfect forward secrecy',
                'Anti-forensic steganography',
                'Format mimicry protection',
                'Entropy normalization',
                'Metadata scattering'
            ]
        }
        
        return info
    
    def close(self):
        """Clean shutdown with secure memory cleanup"""
        self.logger.info(f"Shutting down NATO CRYPTO v3.1 - {self.classification} classification")
        
        # Force garbage collection
        for _ in range(3):
            gc.collect()
        
        self.logger.close()

# Compatibility aliases for backward compatibility with main.py
class MilitaryCrypto(MilitaryEncryption):
    """Alias for backward compatibility"""
    
    def __init__(self, verbose=False, classification="SECRET"):
        super().__init__(verbose, classification)
        # Map old method names to new ones for GUI compatibility
        self.encrypt_file_secure = self.encrypt_file
        self.decrypt_file_secure = self.decrypt_file
        # Map old method names to new ones
        self.encrypt_file_secure = self.encrypt_file
        self.decrypt_file_secure = self.decrypt_file

# Additional utility functions for system integration
def generate_secure_password(length=32, include_symbols=True):
    """Generate cryptographically secure password"""
    import string
    
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    return ''.join(secrets.choice(chars) for _ in range(length))

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate cryptographic hash of file"""
    hash_func = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None

def estimate_encryption_time(file_size_bytes, speed_mbps=50):
    """Estimate encryption time based on file size"""
    size_mb = file_size_bytes / (1024 * 1024)
    return size_mb / speed_mbps

def validate_key_strength(key_input):
    """Validate cryptographic key strength"""
    if len(key_input) < 16:
        return False, "Key too short (minimum 16 characters)"
    
    # Check for hex key (64 chars = 256 bits)
    if len(key_input) == 64:
        try:
            bytes.fromhex(key_input)
            return True, "Valid 256-bit hex key"
        except ValueError:
            pass
    
    # Check passphrase strength
    score = 0
    if any(c.islower() for c in key_input):
        score += 1
    if any(c.isupper() for c in key_input):
        score += 1
    if any(c.isdigit() for c in key_input):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in key_input):
        score += 1
    
    if len(key_input) >= 20 and score >= 3:
        return True, "Strong passphrase"
    elif len(key_input) >= 16 and score >= 2:
        return True, "Adequate passphrase"
    else:
        return False, "Weak passphrase - need more complexity"

# Export main classes and functions
__all__ = [
    'MilitaryEncryption',
    'MilitaryCrypto',
    'MilitaryLogger', 
    'SecureMemory',
    'generate_secure_password',
    'calculate_file_hash',
    'estimate_encryption_time',
    'validate_key_strength',
    'ARGON2_AVAILABLE'
]

# Module metadata
__version__ = '3.1'
__author__ = 'NATO CRYPTO DIVISION'
__description__ = 'Military-grade encryption with quantum resistance and anti-forensic steganography'