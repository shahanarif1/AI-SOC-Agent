#!/usr/bin/env python3
"""
Production DXT packaging script with validation and optimization.
"""

import os
import sys
import json
import zipfile
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List, Set
import tempfile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DXTPackager:
    """Production-grade DXT packaging with validation and optimization."""
    
    def __init__(self, source_dir: Path, output_dir: Path, test_mode: bool = False):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.test_mode = test_mode
        
        # Files to include in DXT package
        self.include_patterns = [
            'manifest.json',
            'src/**/*.py',
            'requirements.txt',
            'README.md',
            'DXT_README.md',
            'LICENSE',
            'icon.png'
        ]
        
        # Files to exclude (in addition to .dxtignore)
        self.exclude_patterns = [
            '**/__pycache__',
            '**/*.pyc',
            '**/*.pyo',
            '**/*.pyd',
            '.git/**',
            '.github/**',
            'tests/**',
            'docs/**',
            '*.log',
            '.env*',
            'venv/**',
            'env/**',
            '.pytest_cache/**',
            '.coverage',
            '*.egg-info/**'
        ]
    
    def validate_manifest(self) -> dict:
        """Validate manifest.json structure and content."""
        manifest_path = self.source_dir / 'manifest.json'
        
        if not manifest_path.exists():
            raise FileNotFoundError("manifest.json not found")
        
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        # Required fields validation
        required_fields = [
            'dxt_version', 'name', 'version', 'description',
            'author', 'server', 'user_config'
        ]
        
        for field in required_fields:
            if field not in manifest:
                raise ValueError(f"Required field '{field}' missing from manifest")
        
        # Server configuration validation
        server_config = manifest['server']
        if server_config['type'] != 'python':
            raise ValueError("Only Python server type supported")
        
        # Validate entry point exists
        entry_point = server_config['entry_point']
        entry_path = self.source_dir / entry_point
        if not entry_path.exists():
            raise FileNotFoundError(f"Entry point '{entry_point}' not found")
        
        # Validate user configuration
        user_config = manifest['user_config']
        required_configs = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
        config_keys = {config['key'] for config in user_config}
        
        for required in required_configs:
            if required not in config_keys:
                raise ValueError(f"Required user config '{required}' missing")
        
        logger.info("✅ Manifest validation passed")
        return manifest
    
    def validate_dependencies(self):
        """Validate Python dependencies and check for security issues."""
        requirements_path = self.source_dir / 'requirements.txt'
        
        if not requirements_path.exists():
            raise FileNotFoundError("requirements.txt not found")
        
        # Check if all dependencies can be resolved
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'check'
            ], capture_output=True, text=True, cwd=self.source_dir)
            
            if result.returncode != 0:
                logger.warning(f"Dependency check warnings: {result.stdout}")
        except Exception as e:
            logger.warning(f"Could not validate dependencies: {e}")
        
        # Security check with safety (if available)
        try:
            result = subprocess.run([
                sys.executable, '-m', 'safety', 'check', '--short-report'
            ], capture_output=True, text=True, cwd=self.source_dir)
            
            if result.returncode != 0:
                logger.warning(f"Security check found issues: {result.stdout}")
            else:
                logger.info("✅ Security check passed")
        except FileNotFoundError:
            logger.info("Safety not installed, skipping security check")
        
        logger.info("✅ Dependencies validated")
    
    def validate_entry_point(self):
        """Validate that the entry point can be imported and executed."""
        try:
            # Add source directory to Python path
            sys.path.insert(0, str(self.source_dir))
            
            # Try to import the main module
            from src.wazuh_mcp_server import main
            
            logger.info("✅ Entry point validation passed")
        except ImportError as e:
            raise ImportError(f"Cannot import entry point: {e}")
        finally:
            # Remove from path
            if str(self.source_dir) in sys.path:
                sys.path.remove(str(self.source_dir))
    
    def read_dxtignore(self) -> Set[str]:
        """Read .dxtignore file and return set of patterns to ignore."""
        dxtignore_path = self.source_dir / '.dxtignore'
        ignore_patterns = set(self.exclude_patterns)
        
        if dxtignore_path.exists():
            with open(dxtignore_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ignore_patterns.add(line)
        
        return ignore_patterns
    
    def should_include_file(self, file_path: Path, ignore_patterns: Set[str]) -> bool:
        """Check if a file should be included in the package."""
        relative_path = file_path.relative_to(self.source_dir)
        
        # Check against ignore patterns
        for pattern in ignore_patterns:
            if relative_path.match(pattern) or str(relative_path).startswith(pattern.rstrip('/**')):
                return False
        
        # Check file size (exclude large files)
        if file_path.is_file() and file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
            logger.warning(f"Excluding large file: {relative_path}")
            return False
        
        return True
    
    def optimize_python_files(self, temp_dir: Path):
        """Optimize Python files by compiling to bytecode."""
        try:
            result = subprocess.run([
                sys.executable, '-m', 'compileall', '-f', str(temp_dir / 'src')
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✅ Python files compiled successfully")
            else:
                logger.warning(f"Python compilation warnings: {result.stderr}")
        except Exception as e:
            logger.warning(f"Could not compile Python files: {e}")
    
    def create_package(self) -> Path:
        """Create the DXT package file."""
        manifest = self.validate_manifest()
        self.validate_dependencies()
        self.validate_entry_point()
        
        package_name = f"{manifest['name']}-{manifest['version']}.dxt"
        if self.test_mode:
            package_name = f"test-{package_name}"
        
        output_path = self.output_dir / package_name
        ignore_patterns = self.read_dxtignore()
        
        logger.info(f"Creating DXT package: {package_name}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Copy files to temporary directory
            files_copied = 0
            for file_path in self.source_dir.rglob('*'):
                if file_path.is_file() and self.should_include_file(file_path, ignore_patterns):
                    relative_path = file_path.relative_to(self.source_dir)
                    dest_path = temp_path / relative_path
                    
                    # Create parent directories
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Copy file
                    shutil.copy2(file_path, dest_path)
                    files_copied += 1
            
            logger.info(f"Copied {files_copied} files to package")
            
            # Optimize Python files if not in test mode
            if not self.test_mode:
                self.optimize_python_files(temp_path)
            
            # Create ZIP archive
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arc_name = file_path.relative_to(temp_path)
                        zf.write(file_path, arc_name)
        
        # Validate the created package
        self.validate_package(output_path)
        
        file_size = output_path.stat().st_size
        logger.info(f"✅ DXT package created: {output_path} ({file_size:,} bytes)")
        
        return output_path
    
    def validate_package(self, package_path: Path):
        """Validate the created DXT package."""
        try:
            with zipfile.ZipFile(package_path, 'r') as zf:
                # Check that required files are present
                file_list = zf.namelist()
                
                required_files = ['manifest.json', 'src/wazuh_mcp_server.py', 'requirements.txt']
                for required_file in required_files:
                    if required_file not in file_list:
                        raise ValueError(f"Required file '{required_file}' missing from package")
                
                # Validate manifest in package
                with zf.open('manifest.json') as f:
                    manifest = json.load(f)
                    if 'dxt_version' not in manifest:
                        raise ValueError("Invalid manifest in package")
                
                logger.info("✅ Package validation passed")
        except Exception as e:
            raise ValueError(f"Package validation failed: {e}")
    
    def generate_checksum(self, package_path: Path) -> str:
        """Generate SHA256 checksum for the package."""
        import hashlib
        
        sha256_hash = hashlib.sha256()
        with open(package_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        checksum = sha256_hash.hexdigest()
        
        # Write checksum file
        checksum_path = package_path.with_suffix('.dxt.sha256')
        with open(checksum_path, 'w') as f:
            f.write(f"{checksum}  {package_path.name}\n")
        
        logger.info(f"✅ Checksum generated: {checksum}")
        return checksum


def main():
    """Main entry point for DXT packaging script."""
    parser = argparse.ArgumentParser(description='Package Wazuh MCP Server as DXT')
    parser.add_argument('--source', type=Path, default=Path.cwd(),
                       help='Source directory (default: current directory)')
    parser.add_argument('--output', type=Path, default=Path.cwd(),
                       help='Output directory (default: current directory)')
    parser.add_argument('--test-mode', action='store_true',
                       help='Run in test mode (skip optimizations)')
    parser.add_argument('--validate-only', action='store_true',
                       help='Only validate, do not create package')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        packager = DXTPackager(args.source, args.output, args.test_mode)
        
        if args.validate_only:
            logger.info("Running validation only...")
            packager.validate_manifest()
            packager.validate_dependencies()
            packager.validate_entry_point()
            logger.info("✅ All validations passed")
        else:
            package_path = packager.create_package()
            checksum = packager.generate_checksum(package_path)
            
            print(f"\n🎉 Success!")
            print(f"📦 Package: {package_path}")
            print(f"🔐 SHA256: {checksum}")
            print(f"\n📋 Next steps:")
            print(f"1. Test the package: Install in Claude Desktop")
            print(f"2. Verify functionality with test Wazuh instance")
            print(f"3. Deploy to production")
    
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()