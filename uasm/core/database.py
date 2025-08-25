"""
Database Interface for UASM
Handles database operations and data persistence
"""

import sqlite3
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from uasm.core.logger import create_module_logger

Base = declarative_base()


class ScanResult(Base):
    """Scan result table model"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    duration = Column(Float)
    status = Column(String(20), nullable=False, default='running')
    modules = Column(Text)  # JSON array
    results_data = Column(Text)  # JSON data
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Add indexes for better performance
    __table_args__ = (
        Index('idx_scan_target', 'target'),
        Index('idx_scan_status', 'status'),
        Index('idx_scan_created', 'created_at'),
    )


class Vulnerability(Base):
    """Vulnerability table model"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Float)
    cve_id = Column(String(20), index=True)
    cwe_id = Column(String(20))
    target_host = Column(String(255), index=True)
    target_port = Column(Integer)
    target_url = Column(String(1000))
    evidence = Column(Text)
    remediation = Column(Text)
    module = Column(String(50), index=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Add indexes for better performance
    __table_args__ = (
        Index('idx_vuln_severity', 'severity'),
        Index('idx_vuln_module', 'module'),
        Index('idx_vuln_host', 'target_host'),
        Index('idx_vuln_discovered', 'discovered_at'),
    )


class Finding(Base):
    """Finding table model"""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    subcategory = Column(String(50))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)
    target = Column(String(500))
    data = Column(Text)  # JSON data
    module = Column(String(50), index=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Add indexes for better performance
    __table_args__ = (
        Index('idx_finding_category', 'category'),
        Index('idx_finding_module', 'module'),
        Index('idx_finding_discovered', 'discovered_at'),
    )


class Host(Base):
    """Host table model"""
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    hostname = Column(String(255), index=True)
    status = Column(String(20), index=True)
    os_family = Column(String(50))
    os_name = Column(String(100))
    mac_address = Column(String(17))
    ports_data = Column(Text)  # JSON data
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Add indexes for better performance
    __table_args__ = (
        Index('idx_host_ip', 'ip_address'),
        Index('idx_host_status', 'status'),
        Index('idx_host_discovered', 'discovered_at'),
    )


class ScanMetadata(Base):
    """Additional scan metadata table"""
    __tablename__ = 'scan_metadata'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), nullable=False, index=True)
    key = Column(String(100), nullable=False)
    value = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_metadata_scan_key', 'scan_id', 'key'),
    )


class Database:
    """Database interface for UASM"""
    
    def __init__(self, config):
        """Initialize database connection"""
        self.config = config
        self.logger = create_module_logger('Database')
        
        # Database configuration
        db_config = self.config.get_section('database')
        self.db_type = db_config.get('type', 'sqlite')
        self.db_name = db_config.get('name', 'uasm_results.db')
        self.db_host = db_config.get('host', 'localhost')
        self.db_port = db_config.get('port', 5432)
        self.db_user = db_config.get('username', '')
        self.db_pass = db_config.get('password', '')
        
        # Initialize database
        self.engine = None
        self.SessionLocal = None
        self._create_engine()
        self._create_tables()
        
        self.logger.info(f"Database initialized: {self.db_type}")
    
    def _create_engine(self):
        """Create database engine"""
        try:
            if self.db_type == 'sqlite':
                # Ensure directory exists
                db_path = Path(self.db_name)
                db_path.parent.mkdir(parents=True, exist_ok=True)
                
                connection_string = f"sqlite:///{self.db_name}"
                self.engine = create_engine(
                    connection_string, 
                    echo=False,
                    poolclass=StaticPool,
                    connect_args={
                        'check_same_thread': False,
                        'timeout': 30
                    }
                )
            
            elif self.db_type == 'postgresql':
                connection_string = f"postgresql://{self.db_user}:{self.db_pass}@{self.db_host}:{self.db_port}/{self.db_name}"
                self.engine = create_engine(
                    connection_string, 
                    echo=False,
                    pool_size=10,
                    max_overflow=20,
                    pool_timeout=30,
                    pool_recycle=3600
                )
            
            elif self.db_type == 'mysql':
                connection_string = f"mysql+pymysql://{self.db_user}:{self.db_pass}@{self.db_host}:{self.db_port}/{self.db_name}"
                self.engine = create_engine(
                    connection_string, 
                    echo=False,
                    pool_size=10,
                    max_overflow=20,
                    pool_timeout=30,
                    pool_recycle=3600
                )
            
            else:
                raise ValueError(f"Unsupported database type: {self.db_type}")
            
            self.SessionLocal = sessionmaker(
                autocommit=False, 
                autoflush=False, 
                bind=self.engine,
                expire_on_commit=False
            )
            
        except Exception as e:
            self.logger.error(f"Failed to create database engine: {str(e)}")
            raise
    
    def _create_tables(self):
        """Create database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.debug("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create tables: {str(e)}")
            raise
    
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
    
    def _parse_datetime(self, dt_input) -> datetime:
        """Parse datetime input safely"""
        if isinstance(dt_input, datetime):
            return dt_input
        elif isinstance(dt_input, str):
            try:
                # Handle ISO format with timezone
                if dt_input.endswith('Z'):
                    dt_input = dt_input[:-1] + '+00:00'
                return datetime.fromisoformat(dt_input)
            except ValueError:
                try:
                    # Try parsing without timezone info
                    return datetime.fromisoformat(dt_input.split('+')[0].split('Z'))
                except ValueError:
                    self.logger.warning(f"Could not parse datetime: {dt_input}")
                    return datetime.utcnow()
        elif isinstance(dt_input, (int, float)):
            # Assume Unix timestamp
            return datetime.fromtimestamp(dt_input)
        else:
            return datetime.utcnow()
    
    def save_scan_result(self, scan_data: Dict[str, Any]) -> str:
        """Save scan results to database"""
        session = self.get_session()
        
        try:
            # Generate scan ID if not provided
            scan_info = scan_data.get('scan_info', {})
            scan_id = scan_info.get('scan_id', f"scan_{int(time.time())}")
            
            # Parse timestamps safely
            start_time = self._parse_datetime(scan_info.get('start_time'))
            end_time = self._parse_datetime(scan_info.get('end_time'))
            
            # Create scan result record
            scan_result = ScanResult(
                scan_id=scan_id,
                target=scan_info.get('target', ''),
                scan_type='comprehensive',
                start_time=start_time,
                end_time=end_time,
                duration=scan_info.get('duration', 0),
                status='completed',
                modules=json.dumps(scan_info.get('modules', [])),
                results_data=json.dumps(scan_data, default=str, ensure_ascii=False)
            )
            
            session.add(scan_result)
            
            # Save vulnerabilities
            for vuln in scan_data.get('vulnerabilities', []):
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=str(vuln.get('title', ''))[:500],  # Ensure length limit
                    description=str(vuln.get('description', '')),
                    severity=str(vuln.get('severity', 'info')).lower(),
                    cvss_score=float(vuln.get('cvss_score', 0)) if vuln.get('cvss_score') else None,
                    cve_id=str(vuln.get('cve_id', ''))[:20] if vuln.get('cve_id') else None,
                    cwe_id=str(vuln.get('cwe_id', ''))[:20] if vuln.get('cwe_id') else None,
                    target_host=str(vuln.get('target_host', ''))[:255] if vuln.get('target_host') else None,
                    target_port=int(vuln.get('target_port')) if vuln.get('target_port') else None,
                    target_url=str(vuln.get('target_url', ''))[:1000] if vuln.get('target_url') else None,
                    evidence=str(vuln.get('evidence', '')) if vuln.get('evidence') else None,
                    remediation=str(vuln.get('remediation', '')) if vuln.get('remediation') else None,
                    module=str(vuln.get('module', ''))[:50],
                    discovered_at=self._parse_datetime(vuln.get('discovered_at'))
                )
                session.add(vulnerability)
            
            # Save findings
            for finding in scan_data.get('findings', []):
                finding_record = Finding(
                    scan_id=scan_id,
                    category=str(finding.get('category', ''))[:50],
                    subcategory=str(finding.get('subcategory', ''))[:50] if finding.get('subcategory') else None,
                    title=str(finding.get('title', ''))[:500],
                    description=str(finding.get('description', '')) if finding.get('description') else None,
                    severity=str(finding.get('severity', 'info')).lower() if finding.get('severity') else None,
                    target=str(finding.get('target', ''))[:500] if finding.get('target') else None,
                    data=json.dumps(finding.get('data', {}), default=str, ensure_ascii=False),
                    module=str(finding.get('module', ''))[:50],
                    discovered_at=self._parse_datetime(finding.get('discovered_at'))
                )
                session.add(finding_record)
            
            # Save hosts
            for host in scan_data.get('hosts', []):
                host_record = Host(
                    scan_id=scan_id,
                    ip_address=str(host.get('ip_address', ''))[:45],
                    hostname=str(host.get('hostname', ''))[:255] if host.get('hostname') else None,
                    status=str(host.get('status', ''))[:20] if host.get('status') else None,
                    os_family=str(host.get('os_family', ''))[:50] if host.get('os_family') else None,
                    os_name=str(host.get('os_name', ''))[:100] if host.get('os_name') else None,
                    mac_address=str(host.get('mac_address', ''))[:17] if host.get('mac_address') else None,
                    ports_data=json.dumps(host.get('ports', []), default=str, ensure_ascii=False),
                    discovered_at=self._parse_datetime(host.get('discovered_at', time.time()))
                )
                session.add(host_record)
            
            session.commit()
            self.logger.info(f"Scan results saved with ID: {scan_id}")
            
            return scan_id
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Failed to save scan results: {str(e)}")
            raise
        finally:
            session.close()
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan results by scan ID"""
        session = self.get_session()
        
        try:
            scan_result = session.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
            
            if not scan_result:
                return None
            
            # Parse results data
            results_data = json.loads(scan_result.results_data)
            
            return results_data
            
        except Exception as e:
            self.logger.error(f"Failed to get scan results: {str(e)}")
            return None
        finally:
            session.close()
    
    def list_scans(self, limit: int = 50, target_filter: str = None) -> List[Dict[str, Any]]:
        """List recent scans with optional filtering"""
        session = self.get_session()
        
        try:
            query = session.query(ScanResult)
            
            if target_filter:
                query = query.filter(ScanResult.target.like(f'%{target_filter}%'))
            
            scans = query.order_by(ScanResult.created_at.desc()).limit(limit).all()
            
            scan_list = []
            for scan in scans:
                scan_info = {
                    'scan_id': scan.scan_id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'start_time': scan.start_time.isoformat() if scan.start_time else None,
                    'end_time': scan.end_time.isoformat() if scan.end_time else None,
                    'duration': scan.duration,
                    'status': scan.status,
                    'modules': json.loads(scan.modules) if scan.modules else [],
                    'created_at': scan.created_at.isoformat() if scan.created_at else None
                }
                scan_list.append(scan_info)
            
            return scan_list
            
        except Exception as e:
            self.logger.error(f"Failed to list scans: {str(e)}")
            return []
        finally:
            session.close()
    
    def get_vulnerabilities(self, scan_id: Optional[str] = None, 
                           severity: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Get vulnerabilities with optional filters"""
        session = self.get_session()
        
        try:
            query = session.query(Vulnerability)
            
            if scan_id:
                query = query.filter(Vulnerability.scan_id == scan_id)
            
            if severity:
                query = query.filter(Vulnerability.severity == severity.lower())
            
            vulnerabilities = query.order_by(Vulnerability.discovered_at.desc()).limit(limit).all()
            
            vuln_list = []
            for vuln in vulnerabilities:
                vuln_dict = {
                    'id': vuln.id,
                    'scan_id': vuln.scan_id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'cvss_score': vuln.cvss_score,
                    'cve_id': vuln.cve_id,
                    'cwe_id': vuln.cwe_id,
                    'target_host': vuln.target_host,
                    'target_port': vuln.target_port,
                    'target_url': vuln.target_url,
                    'evidence': vuln.evidence,
                    'remediation': vuln.remediation,
                    'module': vuln.module,
                    'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None
                }
                vuln_list.append(vuln_dict)
            
            return vuln_list
            
        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {str(e)}")
            return []
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        session = self.get_session()
        
        try:
            stats = {
                'total_scans': session.query(ScanResult).count(),
                'total_vulnerabilities': session.query(Vulnerability).count(),
                'total_findings': session.query(Finding).count(),
                'total_hosts': session.query(Host).count(),
                'vulnerability_by_severity': {},
                'recent_scans': 0,
                'database_type': self.db_type,
                'database_size': self._get_database_size()
            }
            
            # Get vulnerability counts by severity
            severity_results = session.query(
                Vulnerability.severity, 
                session.query(Vulnerability.id).filter(
                    Vulnerability.severity == Vulnerability.severity
                ).count().label('count')
            ).group_by(Vulnerability.severity).all()
            
            for severity, count in severity_results:
                stats['vulnerability_by_severity'][severity] = count
            
            # Get recent scans (last 30 days)
            thirty_days_ago = datetime.utcnow().timestamp() - (30 * 24 * 60 * 60)
            recent_cutoff = datetime.fromtimestamp(thirty_days_ago)
            stats['recent_scans'] = session.query(ScanResult).filter(
                ScanResult.created_at >= recent_cutoff
            ).count()
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {str(e)}")
            return {}
        finally:
            session.close()
    
    def _get_database_size(self) -> str:
        """Get database size"""
        try:
            if self.db_type == 'sqlite':
                db_path = Path(self.db_name)
                if db_path.exists():
                    size_bytes = db_path.stat().st_size
                    return self._format_bytes(size_bytes)
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete scan and all related data"""
        session = self.get_session()
        
        try:
            # Delete in order due to relationships
            session.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
            session.query(Finding).filter(Finding.scan_id == scan_id).delete()
            session.query(Host).filter(Host.scan_id == scan_id).delete()
            session.query(ScanMetadata).filter(ScanMetadata.scan_id == scan_id).delete()
            session.query(ScanResult).filter(ScanResult.scan_id == scan_id).delete()
            
            session.commit()
            self.logger.info(f"Scan {scan_id} deleted successfully")
            
            return True
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Failed to delete scan {scan_id}: {str(e)}")
            return False
        finally:
            session.close()
    
    def cleanup_old_scans(self, days: int = 90) -> int:
        """Clean up scans older than specified days"""
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)
            cutoff_datetime = datetime.fromtimestamp(cutoff_date)
            
            # Get old scan IDs
            old_scans = session.query(ScanResult.scan_id).filter(
                ScanResult.created_at < cutoff_datetime
            ).all()
            
            count = 0
            for (scan_id,) in old_scans:
                if self.delete_scan(scan_id):
                    count += 1
            
            self.logger.info(f"Cleaned up {count} old scans")
            return count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old scans: {str(e)}")
            return 0
        finally:
            session.close()
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            session = self.get_session()
            # Simple query to test connection
            session.query(ScanResult).count()
            session.close()
            return True
        except Exception as e:
            self.logger.error(f"Database connection test failed: {str(e)}")
            return False
    
    def backup_database(self, backup_path: str) -> bool:
        """Backup database (SQLite only)"""
        if self.db_type != 'sqlite':
            self.logger.warning("Database backup only supported for SQLite")
            return False
        
        try:
            import shutil
            shutil.copy2(self.db_name, backup_path)
            self.logger.info(f"Database backed up to: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"Database backup failed: {str(e)}")
            return False
    
    def optimize_database(self) -> bool:
        """Optimize database performance"""
        session = self.get_session()
        
        try:
            if self.db_type == 'sqlite':
                # SQLite optimization
                session.execute("VACUUM")
                session.execute("ANALYZE")
                session.commit()
                self.logger.info("SQLite database optimized")
            else:
                self.logger.info("Database optimization not implemented for this database type")
            
            return True
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database optimization failed: {str(e)}")
            return False
        finally:
            session.close()
    
    def close(self):
        """Close database connection"""
        try:
            if self.engine:
                self.engine.dispose()
                self.logger.debug("Database connection closed")
        except Exception as e:
            self.logger.debug(f"Error closing database: {str(e)}")

