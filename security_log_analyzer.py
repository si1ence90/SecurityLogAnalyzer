#!/usr/bin/env python3
"""
Security Log Analyzer
=====================
A professional security log analysis tool for Windows (.evtx) and Linux (syslog) logs.
Designed for cybersecurity professionals to detect anomalies, threats, and security events.

Author: Security Analysis Team
Version: 1.0.0
"""

import argparse
import html as html_module
import json
import os
import re
import statistics
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import tqdm

# Try to import python-evtx, fallback if not available
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


@dataclass
class LogEntry:
    """
    Unified log entry structure for cross-platform log analysis.
    Contains all core fields for security analysis and risk assessment.
    """
    timestamp: Optional[datetime] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    action_type: Optional[str] = None  # LOGIN_SUCCESS, LOGIN_FAILURE, PRIVILEGE_USE, etc.
    log_source: Optional[str] = None  # syslog, evtx, etc.
    raw_line: Optional[str] = None
    # Risk assessment fields
    risk_score: int = 0
    reasons: List[str] = field(default_factory=list)
    # Legacy fields for compatibility
    username: Optional[str] = None
    event_type: Optional[str] = None
    event_id: Optional[int] = None
    message: Optional[str] = None
    
    def __post_init__(self):
        """Sync username field with user field for backward compatibility."""
        if self.user and not self.username:
            self.username = self.user
        elif self.username and not self.user:
            self.user = self.username


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration parameters
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)


def split_log_file(file_path: str, num_chunks: int) -> List[tuple]:
    """
    Split log file into chunks for parallel processing.
    
    Args:
        file_path: Path to the log file
        num_chunks: Number of chunks to create
        
    Returns:
        List of tuples containing (chunk_id, start_offset, end_offset)
    """
    file_size = os.path.getsize(file_path)
    chunk_size = file_size // num_chunks
    
    chunks = []
    with open(file_path, 'rb') as f:
        for i in range(num_chunks):
            start_offset = i * chunk_size
            if i == num_chunks - 1:
                # Last chunk gets the remainder
                end_offset = file_size
            else:
                end_offset = (i + 1) * chunk_size
                # Try to align to line boundary
                f.seek(end_offset)
                while f.read(1) != b'\n' and f.tell() < file_size:
                    pass
                end_offset = f.tell()
            
            chunks.append((i, start_offset, end_offset))
    
    return chunks


def parse_syslog_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single Linux syslog line and extract security-relevant information.
    
    Args:
        line: Single line from syslog file
        
    Returns:
        LogEntry object if parsing successful, None otherwise
    """
    if not line.strip():
        return None
    
    entry = LogEntry(
        log_source="syslog",
        raw_line=line.strip()
    )
    
    # Common syslog patterns for authentication events
    # Pattern 1: SSH login success: "Jan 15 10:30:45 hostname sshd[1234]: Accepted publickey for user from 192.168.1.1 port 12345 ssh2"
    ssh_success_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\w+)\s+from\s+([\d.]+)'
    match = re.search(ssh_success_pattern, line)
    if match:
        entry.timestamp = parse_syslog_timestamp(match.group(1))
        entry.user = match.group(2)
        entry.source_ip = match.group(3)
        entry.action_type = "LOGIN_SUCCESS"
        return entry
    
    # Pattern 2: SSH login failure: "Jan 15 10:30:45 hostname sshd[1234]: Failed password for user from 192.168.1.1 port 12345 ssh2"
    ssh_failure_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(\w+)\s+from\s+([\d.]+)'
    match = re.search(ssh_failure_pattern, line)
    if match:
        entry.timestamp = parse_syslog_timestamp(match.group(1))
        entry.user = match.group(2)
        entry.source_ip = match.group(3)
        entry.action_type = "LOGIN_FAILURE"
        return entry
    
    # Pattern 3: sudo/privilege use: "Jan 15 10:30:45 hostname sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/su"
    sudo_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo:\s+(\w+)\s+:\s+TTY=.*?;\s+USER=(\w+)'
    match = re.search(sudo_pattern, line)
    if match:
        entry.timestamp = parse_syslog_timestamp(match.group(1))
        entry.user = match.group(2)
        entry.action_type = "PRIVILEGE_USE"
        entry.message = f"User {match.group(2)} used sudo to become {match.group(3)}"
        return entry
    
    # Pattern 4: Generic authentication success/failure
    auth_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+.*?(?:authentication|login).*?(?:success|failed|failure)'
    if re.search(auth_pattern, line, re.IGNORECASE):
        entry.timestamp = parse_syslog_timestamp(re.search(r'\w+\s+\d+\s+\d+:\d+:\d+', line).group() if re.search(r'\w+\s+\d+\s+\d+:\d+:\d+', line) else None)
        # Try to extract IP
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
        if ip_match:
            entry.source_ip = ip_match.group(1)
        # Try to extract username
        user_match = re.search(r'\b(for|user|account)\s+(\w+)', line, re.IGNORECASE)
        if user_match:
            entry.user = user_match.group(2)
        if 'success' in line.lower():
            entry.action_type = "LOGIN_SUCCESS"
        elif 'fail' in line.lower():
            entry.action_type = "LOGIN_FAILURE"
        return entry
    
    return None


def extract_event_id_from_xml(xml_str: str) -> Optional[int]:
    """
    Extract Event ID from XML string using multiple methods.
    
    Args:
        xml_str: XML string (raw or escaped)
        
    Returns:
        Event ID as integer, or None if not found
    """
    event_id = None
    
    # Method 0: Try regex first (fastest and most reliable)
    if 'EventID' in xml_str:
        patterns = [
            r'<EventID[^>]*>(\d+)</EventID>',
            r'<EventID>(\d+)</EventID>',
            r'<EventID[^>]*>(\d+)<',
            r'EventID[^>]*>(\d+)<',
            r'EventID[^>]*>(\d+)</',
            r'<.*EventID[^>]*>(\d+)<',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, xml_str, re.IGNORECASE | re.DOTALL)
            if matches:
                try:
                    event_id = int(matches[0])
                    if 1000 <= event_id <= 99999:
                        break
                except (ValueError, TypeError, IndexError):
                    continue
    
    # Method 1-4: Try XML parsing if regex failed
    if event_id is None:
        try:
            import xml.etree.ElementTree as ET
            ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            root = ET.fromstring(xml_str)
            
            # Method 1: Try with namespace
            event_id_elem = root.find('.//evt:EventID', ns)
            if event_id_elem is not None and event_id_elem.text:
                try:
                    event_id = int(event_id_elem.text)
                except (ValueError, TypeError):
                    pass
            
            # Method 2: Try without namespace
            if event_id is None:
                event_id_elem = root.find('.//EventID')
                if event_id_elem is not None and event_id_elem.text:
                    try:
                        event_id = int(event_id_elem.text)
                    except (ValueError, TypeError):
                        pass
            
            # Method 3: Try System/EventID path
            if event_id is None:
                system_elem = root.find('.//evt:System', ns) or root.find('.//System')
                if system_elem is not None:
                    event_id_elem = system_elem.find('.//evt:EventID', ns) or system_elem.find('.//EventID')
                    if event_id_elem is not None and event_id_elem.text:
                        try:
                            event_id = int(event_id_elem.text)
                        except (ValueError, TypeError):
                            pass
        except Exception:
            pass
    
    return event_id


def parse_evtx_event(raw_xml: str, event_xml: str) -> Optional[LogEntry]:
    """
    Parse a Windows EVTX event record and extract security-relevant information.
    
    Args:
        raw_xml: Raw XML string from record.xml()
        event_xml: Escaped XML string for parsing
        
    Returns:
        LogEntry object if parsing successful, None otherwise
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Extract event ID using the proven extract_event_id_from_xml function
        event_id = extract_event_id_from_xml(raw_xml)
        
        # If that fails, try event_xml
        if event_id is None:
            event_id = extract_event_id_from_xml(event_xml)
        
        if event_id is None:
            return None
        
        # Parse XML for other data
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(event_xml)
        
        # Get timestamp
        time_created_elem = root.find('.//evt:TimeCreated', ns)
        if time_created_elem is None:
            time_created_elem = root.find('.//TimeCreated')
        
        timestamp = None
        if time_created_elem is not None:
            time_attr = time_created_elem.get('SystemTime')
            if time_attr:
                try:
                    # Parse format: 2024-01-15T10:30:45.123456Z
                    timestamp = datetime.fromisoformat(time_attr.replace('Z', '+00:00'))
                except:
                    pass
        
        entry = LogEntry(
            log_source="evtx",
            event_id=event_id,
            timestamp=timestamp,
            raw_line=raw_xml[:500] if raw_xml else None  # Store first 500 chars of raw XML
        )
        
        # Parse EventData
        event_data = root.find('.//evt:EventData', ns)
        if event_data is None:
            event_data = root.find('.//EventData')
        
        data_dict = {}
        if event_data is not None:
            # Try to find Data elements with namespace first, then without
            data_elems = event_data.findall('.//evt:Data', ns)
            if not data_elems:
                data_elems = event_data.findall('.//Data')
            
            for data_elem in data_elems:
                name = data_elem.get('Name')
                value = data_elem.text if data_elem.text else ''
                if name:
                    data_dict[name] = value
        
        # Map Windows Event IDs to action types
        # Event ID 4624: Successful logon
        if event_id == 4624:
            entry.action_type = "LOGIN_SUCCESS"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.source_ip = data_dict.get('IpAddress') or data_dict.get('IpPort')
            if not entry.source_ip or entry.source_ip == '-':
                entry.source_ip = data_dict.get('WorkstationName')
            entry.message = f"Successful logon: {entry.user} from {entry.source_ip}"
        
        # Event ID 4625: Failed logon
        elif event_id == 4625:
            entry.action_type = "LOGIN_FAILURE"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.source_ip = data_dict.get('IpAddress') or data_dict.get('IpPort')
            if not entry.source_ip or entry.source_ip == '-':
                entry.source_ip = data_dict.get('WorkstationName')
            failure_reason = data_dict.get('SubStatus', 'Unknown')
            entry.message = f"Failed logon: {entry.user} from {entry.source_ip} (Reason: {failure_reason})"
        
        # Event ID 4672: Special privileges assigned to new logon
        elif event_id == 4672:
            entry.action_type = "PRIVILEGE_USE"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            privileges = data_dict.get('PrivilegeList', '')
            entry.message = f"Special privileges assigned: {entry.user} ({privileges})"
        
        # Event ID 4648: A logon was attempted using explicit credentials
        elif event_id == 4648:
            entry.action_type = "LOGIN_SUCCESS"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.source_ip = data_dict.get('IpAddress')
            entry.message = f"Explicit credentials logon: {entry.user}"
        
        # Event ID 4768: A Kerberos authentication ticket (TGT) was requested
        elif event_id == 4768:
            entry.action_type = "LOGIN_SUCCESS"
            entry.user = data_dict.get('TargetUserName')
            entry.source_ip = data_dict.get('IpAddress')
            entry.message = f"Kerberos TGT requested: {entry.user}"
        
        # Event ID 4769: A Kerberos service ticket was requested
        elif event_id == 4769:
            entry.action_type = "LOGIN_SUCCESS"
            entry.user = data_dict.get('TargetUserName')
            entry.source_ip = data_dict.get('IpAddress')
            entry.message = f"Kerberos service ticket requested: {entry.user}"
        
        # Event ID 4776: The computer attempted to validate the credentials for an account
        elif event_id == 4776:
            entry.action_type = "LOGIN_FAILURE"
            entry.user = data_dict.get('TargetUserName')
            entry.source_ip = data_dict.get('IpAddress')
            entry.message = f"Credential validation failed: {entry.user}"
        
        # Event ID 4728: A member was added to a security-enabled global group
        # Event ID 4732: A member was added to a security-enabled local group
        elif event_id in [4728, 4732]:
            entry.action_type = "PRIVILEGE_USE"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.message = f"Group membership change: {entry.user}"
        
        # Event ID 4627: Group membership information
        elif event_id == 4627:
            entry.action_type = "LOGIN_SUCCESS"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.source_ip = data_dict.get('IpAddress') or data_dict.get('WorkstationName')
            entry.message = f"Group membership information: {entry.user}"
        
        # Event ID 4798: User account local group membership was enumerated
        elif event_id == 4798:
            entry.action_type = "PRIVILEGE_USE"
            entry.user = data_dict.get('TargetUserName') or data_dict.get('SubjectUserName')
            entry.message = f"Group membership enumeration: {entry.user}"
        
        # If we have a user but no action type, set a generic one
        if entry.user and not entry.action_type:
            entry.action_type = "EVENT"
            entry.message = f"Event {event_id}: {entry.user}"
        
        # Try to extract user from other common fields if not found
        if not entry.user:
            # Try common user field names
            for field_name in ['TargetUserName', 'SubjectUserName', 'AccountName', 'UserName', 
                              'NewTargetUserName', 'OldTargetUserName', 'MemberName']:
                if field_name in data_dict and data_dict[field_name]:
                    entry.user = data_dict[field_name]
                    break
        
        # Try to extract IP from other common fields
        if not entry.source_ip:
            for field_name in ['IpAddress', 'IpPort', 'WorkstationName', 'SourceNetworkAddress', 
                              'ClientAddress', 'SourceAddress']:
                if field_name in data_dict and data_dict[field_name] and data_dict[field_name] != '-':
                    entry.source_ip = data_dict[field_name]
                    break
        
        # For security-related event IDs (even if not in our specific list), try to create entry
        # Security event IDs typically range from 4600-6000, but we'll also try other ranges
        # Some Windows versions use different event ID ranges
        is_security_event = (4600 <= event_id <= 6000) or (event_id >= 1000 and event_id <= 99999)
        
        if is_security_event:
            if not entry.action_type:
                # Try to infer action type from event ID range
                if event_id in range(4624, 4635):  # Logon events
                    entry.action_type = "LOGIN_SUCCESS" if event_id == 4624 else "LOGIN_FAILURE"
                elif event_id in range(4648, 4650):  # Explicit credentials
                    entry.action_type = "LOGIN_SUCCESS"
                elif event_id in range(4672, 4675):  # Privilege events
                    entry.action_type = "PRIVILEGE_USE"
                elif event_id in range(4768, 4772):  # Kerberos
                    entry.action_type = "LOGIN_SUCCESS"
                elif event_id in range(4776, 4779):  # Credential validation
                    entry.action_type = "LOGIN_FAILURE"
                else:
                    entry.action_type = "SECURITY_EVENT"
            
            if not entry.message:
                entry.message = f"Security Event {event_id}"
        
        # Always return entry if we have event_id and it's a security event
        # Even if we don't have user, we should return it for security analysis
        if event_id:
            # For security event IDs (4600-6000), always return
            if 4600 <= event_id <= 6000:
                if not entry.action_type:
                    entry.action_type = "SECURITY_EVENT"
                if not entry.message:
                    entry.message = f"Security Event {event_id}"
                return entry
            # For other known security event IDs
            elif event_id in [4624, 4625, 4627, 4672, 4798, 4648, 4768, 4769, 4776, 4728, 4732]:
                if not entry.action_type:
                    entry.action_type = "SECURITY_EVENT"
                if not entry.message:
                    entry.message = f"Security Event {event_id}"
                return entry
            # For any event with action_type or user
            elif entry.action_type or entry.user:
                return entry
        
    except Exception as e:
        # Silently skip parsing errors for individual events
        # But log the error for debugging
        pass
    
    return None


def parse_evtx_file(file_path: str) -> List[LogEntry]:
    """
    Parse a Windows EVTX file and extract security-relevant events.
    
    Strategy:
    1. First try to parse first 50 records to test extraction method
    2. If extraction fails (success rate < 50%), immediately switch to alternative method
    3. If all methods fail, immediately abort and raise error
    
    Args:
        file_path: Path to the EVTX file
        
    Returns:
        List of parsed LogEntry objects
    """
    if not EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx library is not installed. "
            "Please install it using: pip install python-evtx"
        )
    
    TEST_SAMPLE_SIZE = 50  # Test first 50 records
    MIN_SUCCESS_RATE = 0.5  # Minimum 50% success rate to continue with method
    
    def parse_record(record, use_parse_evtx_event=True):
        """Helper function to parse a single record."""
        try:
            xml_str = record.xml()
            if not xml_str or not isinstance(xml_str, str):
                return None, None
            
            raw_xml = xml_str
            try:
                event_xml = e_views.XML_HEADER
                event_xml += e_views.xmlescape(raw_xml)
            except:
                # If xmlescape fails, use raw_xml directly
                event_xml = raw_xml
            
            # Extract event ID using regex - PROVEN pattern from test script
            # The XML format is: <EventID Qualifiers="">4798</EventID>
            # Test script confirmed this pattern works: r'<EventID[^>]*>(\d+)</EventID>'
            event_id = None
            if 'EventID' in xml_str:
                patterns = [
                    r'<EventID[^>]*>(\d+)</EventID>',  # Most common format - PROVEN TO WORK
                    r'<EventID>(\d+)</EventID>',
                    r'EventID[^>]*>(\d+)',
                ]
                for pattern in patterns:
                    try:
                        matches = re.findall(pattern, xml_str, re.IGNORECASE | re.DOTALL)
                        if matches:
                            try:
                                candidate_id = int(matches[0])
                                if 1000 <= candidate_id <= 99999:
                                    event_id = candidate_id
                                    break
                            except (ValueError, TypeError, IndexError):
                                continue
                    except Exception:
                        continue
            
            # Parse event entry
            entry = None
            if use_parse_evtx_event:
                entry = parse_evtx_event(raw_xml, event_xml)
            
            # If parse_evtx_event failed but we have event_id, create basic entry
            if entry is None and event_id is not None and (4600 <= event_id <= 6000 or event_id in [4624, 4625, 4627, 4672, 4798]):
                try:
                    import xml.etree.ElementTree as ET
                    ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    root = ET.fromstring(event_xml)
                    time_created_elem = root.find('.//evt:TimeCreated', ns) or root.find('.//TimeCreated')
                    timestamp = None
                    if time_created_elem is not None:
                        time_attr = time_created_elem.get('SystemTime')
                        if time_attr:
                            try:
                                timestamp = datetime.fromisoformat(time_attr.replace('Z', '+00:00'))
                            except:
                                pass
                    
                    entry = LogEntry(
                        log_source="evtx",
                        event_id=event_id,
                        timestamp=timestamp,
                        raw_line=raw_xml[:500] if raw_xml else None,
                        action_type="SECURITY_EVENT" if event_id >= 4600 else "EVENT"
                    )
                except:
                    pass
            
            return event_id, entry
        except Exception:
            return None, None
    
    entries = []
    event_id_counts = defaultdict(int)
    
    print("Parsing EVTX file...")
    print(f"Testing first {TEST_SAMPLE_SIZE} records to validate extraction method...")
    
    # Step 1: Test first 50 records
    test_success_count = 0
    test_total = 0
    test_entries = []
    test_sample_xmls = []
    
    try:
        with evtx.Evtx(file_path) as log:
            # Test phase: parse first 50 records
            for record in log.records():
                if test_total >= TEST_SAMPLE_SIZE:
                    break
                test_total += 1
                event_id, entry = parse_record(record)
                
                if event_id is not None:
                    test_success_count += 1
                    event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                    if entry:
                        test_entries.append(entry)
                else:
                    if len(test_sample_xmls) < 3:
                        try:
                            xml_str = record.xml()
                            test_sample_xmls.append(xml_str[:2000] if xml_str else '')
                        except:
                            pass
            
            # Calculate success rate
            success_rate = test_success_count / test_total if test_total > 0 else 0
            print(f"Test results: {test_success_count}/{test_total} records successfully extracted event IDs ({success_rate*100:.1f}% success rate)")
            
            # Step 2: If success rate is too low, try alternative method
            if success_rate < MIN_SUCCESS_RATE:
                print(f"\n[WARNING] Primary extraction method failed (success rate: {success_rate*100:.1f}% < {MIN_SUCCESS_RATE*100:.0f}%)")
                print("Switching to alternative parsing method...")
                
                # Try alternative method on test sample
                alt_success_count = 0
                alt_test_total = 0
                with evtx.Evtx(file_path) as log2:
                    for record in log2.records():
                        if alt_test_total >= TEST_SAMPLE_SIZE:
                            break
                        alt_test_total += 1
                        event_id, entry = parse_record(record, use_parse_evtx_event=False)
                        
                        if event_id is not None:
                            alt_success_count += 1
                            if entry:
                                test_entries.append(entry)
                
                alt_success_rate = alt_success_count / alt_test_total if alt_test_total > 0 else 0
                print(f"Alternative method test: {alt_success_count}/{alt_test_total} records successfully extracted ({alt_success_rate*100:.1f}% success rate)")
                
                # If alternative also fails, abort immediately
                if alt_success_rate < MIN_SUCCESS_RATE:
                    error_msg = f"\n[CRITICAL] All extraction methods failed!\n"
                    error_msg += f"Primary method: {success_rate*100:.1f}% success rate\n"
                    error_msg += f"Alternative method: {alt_success_rate*100:.1f}% success rate\n"
                    error_msg += f"Minimum required: {MIN_SUCCESS_RATE*100:.0f}%\n\n"
                    error_msg += "This suggests the EVTX file may:\n"
                    error_msg += "  1. Use a different XML namespace or structure\n"
                    error_msg += "  2. Be corrupted or in an unsupported format\n"
                    error_msg += "  3. Be from a different Windows version with different event log format\n"
                    
                    if test_sample_xmls:
                        error_msg += "\nSample XML from first failed record (first 1000 chars):\n"
                        error_msg += "=" * 70 + "\n"
                        try:
                            sample_text = test_sample_xmls[0][:1000]
                            sample_text = sample_text.encode('ascii', 'replace').decode('ascii')
                            error_msg += sample_text + "\n"
                        except:
                            error_msg += "Could not display sample XML\n"
                        error_msg += "=" * 70 + "\n"
                    
                    raise ValueError(error_msg)
                
                # Alternative method works, use it for all records
                print(f"Alternative method validated. Processing all records...")
                entries = test_entries.copy()
                with evtx.Evtx(file_path) as log3:
                    with tqdm.tqdm(desc="Processing events", unit="event", initial=TEST_SAMPLE_SIZE) as pbar:
                        record_iter = iter(log3.records())
                        # Skip already processed records
                        for _ in range(TEST_SAMPLE_SIZE):
                            next(record_iter, None)
                        
                        for record in record_iter:
                            event_id, entry = parse_record(record, use_parse_evtx_event=False)
                            if event_id is not None:
                                event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                                if entry:
                                    entries.append(entry)
                            pbar.update(1)
            else:
                # Primary method works, continue with all records
                print(f"Primary extraction method validated. Processing all records...")
                entries = test_entries.copy()
                with evtx.Evtx(file_path) as log3:
                    with tqdm.tqdm(desc="Processing events", unit="event", initial=TEST_SAMPLE_SIZE) as pbar:
                        record_iter = iter(log3.records())
                        # Skip already processed records
                        for _ in range(TEST_SAMPLE_SIZE):
                            next(record_iter, None)
                        
                        for record in record_iter:
                            event_id, entry = parse_record(record)
                            if event_id is not None:
                                event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                                if entry:
                                    entries.append(entry)
                            pbar.update(1)
            
            # Final summary
            total_records = len(entries) + (test_total if test_total > 0 else 0)
            print(f"\nParsing completed.")
            print(f"Detected {len(event_id_counts)} unique event IDs.")
            print(f"Parsed {len(entries)} security-relevant events.")
            
            # Show top event IDs
            if event_id_counts:
                print("\nTop 10 Event IDs in file:")
                for event_id, count in sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  Event ID {event_id}: {count:,} occurrences")
                print()
                        
    except UnicodeEncodeError as e:
        # Handle encoding errors on Windows console
        import sys
        import io
        # Try to use UTF-8 encoding for output
        if sys.stdout.encoding and 'utf' not in sys.stdout.encoding.lower():
            # Re-encode the error message safely
            error_msg = f"Error parsing EVTX file: Encoding issue detected. {str(e)[:100]}"
            raise Exception(error_msg)
        else:
            raise Exception(f"Error parsing EVTX file: {e}")
    except Exception as e:
        raise Exception(f"Error parsing EVTX file: {e}")
    
    return entries


def parse_syslog_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse syslog timestamp string to datetime object.
    
    Args:
        timestamp_str: Timestamp string like "Jan 15 10:30:45"
        
    Returns:
        datetime object or None if parsing fails
    """
    if not timestamp_str:
        return None
    
    try:
        # Get current year for relative timestamp parsing
        current_year = datetime.now().year
        # Parse format: "Jan 15 10:30:45"
        dt = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y")
        return dt
    except ValueError:
        try:
            # Try alternative format
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt
        except ValueError:
            return None


def parse_log_chunk(args: tuple) -> List[LogEntry]:
    """
    Parse a chunk of log file (worker function for multiprocessing).
    
    Args:
        args: Tuple containing (file_path, chunk_id, start_offset, end_offset)
        
    Returns:
        List of parsed LogEntry objects
    """
    file_path, chunk_id, start_offset, end_offset = args
    
    file_ext = Path(file_path).suffix.lower()
    entries = []
    
    try:
        # Handle text-based log files (syslog, etc.)
        # Note: EVTX files are handled separately in parse_log() and never reach this function
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(start_offset)
            # Skip partial line at start (unless it's the first chunk)
            if start_offset > 0:
                f.readline()
            
            current_pos = f.tell()
            while current_pos < end_offset:
                line = f.readline()
                if not line:
                    break
                
                current_pos = f.tell()
                
                if file_ext in ['.log', '.txt', ''] or 'syslog' in Path(file_path).name.lower():
                    # Linux syslog format - implemented
                    entry = parse_syslog_line(line)
                    if entry:
                        entries.append(entry)
                else:
                    # Unknown format - try generic parsing
                    entry = parse_syslog_line(line)
                    if entry:
                        entries.append(entry)
    except Exception as e:
        print(f"[Chunk {chunk_id}] Error reading file: {e}")
    
    return entries


def parse_log(file_path: str, num_processes: int = 4) -> List[LogEntry]:
    """
    Main log parsing function with multiprocessing support.
    
    Args:
        file_path: Path to the log file
        num_processes: Number of parallel processes to use (not used for EVTX files)
        
    Returns:
        List of all parsed LogEntry objects
    """
    file_ext = Path(file_path).suffix.lower()
    
    # Handle EVTX files separately (binary structured format, cannot be chunked)
    if file_ext == '.evtx':
        print(f"Detected log format: Windows Event Log (.evtx)")
        
        if not EVTX_AVAILABLE:
            print("=" * 70)
            print("ERROR: python-evtx library is not installed.")
            print("=" * 70)
            print("Please install it using:")
            print("  pip install python-evtx")
            print()
            print("Or install all dependencies:")
            print("  pip install -r requirements.txt")
            print("=" * 70)
            sys.exit(1)
        
        print("Parsing EVTX file (this may take a while for large files)...")
        print()
        
        try:
            all_entries = parse_evtx_file(file_path)
            print(f"Parsed {len(all_entries)} security-relevant events from EVTX file.")
            # Sort entries by timestamp
            all_entries.sort(key=lambda x: x.timestamp if x.timestamp else datetime.min)
            return all_entries
        except Exception as e:
            print(f"Error parsing EVTX file: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    # Handle text-based log files (syslog, etc.) with multiprocessing
    elif file_ext in ['.log', '.txt', ''] or 'syslog' in Path(file_path).name.lower():
        print(f"Detected log format: Linux syslog")
    else:
        print(f"Warning: Unknown file extension '{file_ext}', attempting syslog parsing")
    
    # Split file into chunks for parallel processing
    chunks = split_log_file(file_path, num_processes)
    
    all_entries = []
    
    # Process chunks in parallel with progress bar
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        # Submit all tasks
        future_to_chunk = {
            executor.submit(parse_log_chunk, (file_path, chunk_id, start, end)): chunk_id
            for chunk_id, start, end in chunks
        }
        
        # Process results with progress bar
        with tqdm.tqdm(total=len(chunks), desc="Processing log chunks", unit="chunk") as pbar:
            for future in as_completed(future_to_chunk):
                chunk_id = future_to_chunk[future]
                try:
                    entries = future.result()
                    all_entries.extend(entries)
                    pbar.update(1)
                except Exception as e:
                    print(f"\nError processing chunk {chunk_id}: {e}")
                    pbar.update(1)
    
    # Sort entries by timestamp
    all_entries.sort(key=lambda x: x.timestamp if x.timestamp else datetime.min)
    
    return all_entries


def calculate_baselines(all_log_entries: List[LogEntry], config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Calculate statistical baselines for each user based on historical log data.
    Phase 1: Dynamic Baseline Modeling (Statistical Baseline Modeling)
    
    Args:
        all_log_entries: List of all parsed log entries
        config: Configuration dictionary
        
    Returns:
        Dictionary mapping username to baseline statistics
    """
    user_baselines = defaultdict(lambda: {
        'login_times': [],
        'ip_frequency': defaultdict(int),
        'total_logins': 0,
        'last_login_time': None,
        'last_login_ip': None
    })
    
    # Process all successful login entries
    for entry in all_log_entries:
        if entry.action_type == "LOGIN_SUCCESS" and entry.user and entry.timestamp:
            user = entry.user
            baseline = user_baselines[user]
            
            # Collect login times (convert to hours since midnight for time-of-day analysis)
            login_hour = entry.timestamp.hour + entry.timestamp.minute / 60.0
            baseline['login_times'].append(login_hour)
            baseline['total_logins'] += 1
            
            # Track IP frequency
            if entry.source_ip:
                baseline['ip_frequency'][entry.source_ip] += 1
            
            # Update last login record
            if baseline['last_login_time'] is None or entry.timestamp > baseline['last_login_time']:
                baseline['last_login_time'] = entry.timestamp
                baseline['last_login_ip'] = entry.source_ip
    
    # Calculate statistics for each user
    for user, baseline in user_baselines.items():
        login_times = baseline['login_times']
        if len(login_times) > 1:
            baseline['login_time_mean'] = statistics.mean(login_times)
            baseline['login_time_std'] = statistics.stdev(login_times) if len(login_times) > 1 else 0.0
        elif len(login_times) == 1:
            baseline['login_time_mean'] = login_times[0]
            baseline['login_time_std'] = 0.0
        else:
            baseline['login_time_mean'] = None
            baseline['login_time_std'] = None
        
        # Calculate IP frequency percentages
        total_ip_uses = sum(baseline['ip_frequency'].values())
        if total_ip_uses > 0:
            baseline['ip_frequency_pct'] = {
                ip: count / total_ip_uses
                for ip, count in baseline['ip_frequency'].items()
            }
        else:
            baseline['ip_frequency_pct'] = {}
    
    return dict(user_baselines)


def detect_anomalies(log_entry: LogEntry, user_baselines: Dict[str, Dict[str, Any]], 
                     config: Dict[str, Any], failure_counts: Dict[Tuple[str, str], List[datetime]],
                     user_last_login: Dict[str, Dict[str, Any]]) -> LogEntry:
    """
    Detect anomalies in a log entry and assign risk scores.
    Phase 2: Advanced Anomaly Detection with Dynamic Risk Scoring (Hybrid Strategy)
    
    Args:
        log_entry: Log entry to analyze
        user_baselines: User baseline statistics dictionary
        config: Configuration dictionary
        failure_counts: Dictionary tracking login failures by (user, ip) tuple
        user_last_login: Dictionary tracking last login time and IP for each user (runtime state)
        
    Returns:
        LogEntry with updated risk_score and reasons
    """
    risk_score = 0
    reasons = []
    
    # 1. Brute-Force Detection (Simple Statistical)
    if log_entry.action_type == "LOGIN_FAILURE" and log_entry.user and log_entry.source_ip:
        key = (log_entry.user, log_entry.source_ip)
        if key not in failure_counts:
            failure_counts[key] = []
        failure_counts[key].append(log_entry.timestamp)
        
        # Check failures in last 60 seconds
        if log_entry.timestamp:
            cutoff_time = log_entry.timestamp - timedelta(seconds=60)
            recent_failures = [t for t in failure_counts[key] if t >= cutoff_time]
            
            threshold = config.get('BRUTE_FORCE_RATE_THRESHOLD', 5)
            if len(recent_failures) >= threshold:
                risk_score += 8
                reasons.append(f"Brute-force attack detected: {len(recent_failures)} failures in 60s from {log_entry.source_ip}")
    
    # 2. Hard-coded Rule: Privilege Account Usage
    if log_entry.user and log_entry.user in config.get('HIGH_PRIVILEGE_ACCOUNTS', []):
        risk_score += 3
        reasons.append(f"High privilege account '{log_entry.user}' used")
    
    # 3. Hard-coded Rule: Service Account Interactive Login
    if log_entry.user and log_entry.user in config.get('KNOWN_SERVICE_ACCOUNTS', []):
        # Check if it's an interactive login (SSH, RDP, etc.)
        if log_entry.action_type == "LOGIN_SUCCESS" and log_entry.source_ip:
            risk_score += 10
            reasons.append(f"Service account '{log_entry.user}' used for interactive login from {log_entry.source_ip}")
    
    # 4. Dynamic Baseline: Time Anomaly
    if log_entry.action_type == "LOGIN_SUCCESS" and log_entry.user and log_entry.timestamp:
        user = log_entry.user
        if user in user_baselines:
            baseline = user_baselines[user]
            if baseline.get('login_time_mean') is not None and baseline.get('login_time_std') is not None:
                login_hour = log_entry.timestamp.hour + log_entry.timestamp.minute / 60.0
                mean = baseline['login_time_mean']
                std = baseline['login_time_std']
                multiplier = config.get('TIME_ANOMALY_STD_MULTIPLIER', 2.5)
                
                if std > 0 and abs(login_hour - mean) > multiplier * std:
                    risk_score += 4
                    reasons.append(f"Anomalous login time: {login_hour:.2f}h (normal: {mean:.2f}h ± {multiplier * std:.2f}h)")
    
    # 5. Dynamic Baseline: Infrequent IP
    if log_entry.action_type == "LOGIN_SUCCESS" and log_entry.user and log_entry.source_ip:
        user = log_entry.user
        if user in user_baselines:
            baseline = user_baselines[user]
            ip_freq_pct = baseline.get('ip_frequency_pct', {})
            threshold = config.get('INFREQUENT_IP_THRESHOLD', 0.05)
            
            ip_frequency = ip_freq_pct.get(log_entry.source_ip, 0.0)
            if ip_frequency < threshold and len(ip_freq_pct) > 0:  # Only flag if user has history
                risk_score += 5
                reasons.append(f"Infrequent IP login: {log_entry.source_ip} (frequency: {ip_frequency*100:.2f}%, threshold: {threshold*100}%)")
    
    # 6. Advanced Scenario: Impossible Travel (Simplified)
    if log_entry.action_type == "LOGIN_SUCCESS" and log_entry.user and log_entry.source_ip and log_entry.timestamp:
        user = log_entry.user
        # Use runtime state for last login (not baseline, which may include future entries)
        if user in user_last_login:
            last_time = user_last_login[user].get('time')
            last_ip = user_last_login[user].get('ip')
            
            if last_time and last_ip and last_ip != log_entry.source_ip:
                time_diff = (log_entry.timestamp - last_time).total_seconds()
                min_seconds = config.get('IMPOSSIBLE_TRAVEL_MIN_SECONDS', 3600)
                
                if 0 < time_diff < min_seconds:
                    risk_score += 7
                    reasons.append(f"Impossible travel detected: login from {last_ip} to {log_entry.source_ip} in {time_diff:.0f}s (min: {min_seconds}s)")
        
        # Update runtime state for next iteration
        user_last_login[user] = {
            'time': log_entry.timestamp,
            'ip': log_entry.source_ip
        }
    
    # Update log entry
    log_entry.risk_score = risk_score
    log_entry.reasons = reasons
    
    return log_entry


def calculate_statistics(all_entries: List[LogEntry], log_file: str) -> Dict[str, Any]:
    """
    Calculate comprehensive statistics about the log analysis.
    
    Args:
        all_entries: List of all parsed log entries
        log_file: Path to the original log file
        
    Returns:
        Dictionary containing statistics
    """
    stats = {
        'total_entries': len(all_entries),
        'total_log_lines': 0,
        'earliest_timestamp': None,
        'latest_timestamp': None,
        'time_span_hours': 0,
        'anomaly_count': 0,
        'high_risk_count': 0,
        'medium_risk_count': 0,
        'unique_users': set(),
        'unique_ips': set(),
        'action_type_counts': defaultdict(int)
    }
    
    # Count total log lines (estimate from file if available)
    # For EVTX files, use entry count as line count
    file_ext = Path(log_file).suffix.lower()
    if file_ext == '.evtx':
        stats['total_log_lines'] = len(all_entries)
    else:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                stats['total_log_lines'] = sum(1 for _ in f)
        except:
            stats['total_log_lines'] = len(all_entries)  # Fallback
    
    # Process entries
    timestamps = []
    for entry in all_entries:
        if entry.timestamp:
            timestamps.append(entry.timestamp)
        
        if entry.risk_score > 0:
            stats['anomaly_count'] += 1
            if entry.risk_score >= 7:
                stats['high_risk_count'] += 1
            elif entry.risk_score >= 3:
                stats['medium_risk_count'] += 1
        
        if entry.user:
            stats['unique_users'].add(entry.user)
        
        if entry.source_ip:
            stats['unique_ips'].add(entry.source_ip)
        
        if entry.action_type:
            stats['action_type_counts'][entry.action_type] += 1
    
    # Calculate time span
    if timestamps:
        stats['earliest_timestamp'] = min(timestamps)
        stats['latest_timestamp'] = max(timestamps)
        if stats['earliest_timestamp'] and stats['latest_timestamp']:
            time_diff = stats['latest_timestamp'] - stats['earliest_timestamp']
            stats['time_span_hours'] = time_diff.total_seconds() / 3600.0
    
    # Convert sets to counts
    stats['unique_user_count'] = len(stats['unique_users'])
    stats['unique_ip_count'] = len(stats['unique_ips'])
    stats['unique_users'] = sorted(list(stats['unique_users']))
    stats['unique_ips'] = sorted(list(stats['unique_ips']))
    
    return stats


def generate_brief_report(results: List[LogEntry], stats: Dict[str, Any], user_baselines: Dict[str, Dict[str, Any]] = None, output_path: str = "brief_report.md"):
    """
    Generate a brief actionable summary report with high and medium risk events only.
    
    Args:
        results: List of LogEntry objects with risk scores
        stats: Statistics dictionary
        output_path: Path to output markdown file
    """
    # Filter for high and medium risk events (risk_score >= 3)
    filtered_results = [entry for entry in results if entry.risk_score >= 3]
    # Sort by risk score descending
    filtered_results.sort(key=lambda x: x.risk_score, reverse=True)
    
    # Calculate alert type statistics
    alert_type_counts = defaultdict(int)
    alert_type_details = defaultdict(list)  # Store sample entries for each alert type
    
    for entry in filtered_results:
        if entry.reasons:
            for reason in entry.reasons:
                # Categorize alert types
                if "Brute-force" in reason or "brute-force" in reason.lower():
                    alert_type = "Brute-Force Attack"
                elif "High privilege account" in reason:
                    alert_type = "High Privilege Account Usage"
                elif "Service account" in reason and "interactive" in reason.lower():
                    alert_type = "Service Account Abuse"
                elif "Anomalous login time" in reason:
                    alert_type = "Anomalous Login Time"
                elif "Infrequent IP" in reason:
                    alert_type = "Infrequent IP Login"
                elif "Impossible travel" in reason:
                    alert_type = "Impossible Travel"
                else:
                    alert_type = "Other Security Event"
                
                alert_type_counts[alert_type] += 1
                if len(alert_type_details[alert_type]) < 3:  # Store up to 3 examples
                    alert_type_details[alert_type].append({
                        'timestamp': entry.timestamp,
                        'user': entry.user,
                        'source_ip': entry.source_ip,
                        'reason': reason
                    })
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# Security Log Analysis - Brief Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Anomalies:** {len(filtered_results)} (High Risk: {stats['high_risk_count']}, Medium Risk: {stats['medium_risk_count']})\n")
        f.write(f"- **Analysis Period:** {stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['earliest_timestamp'] else 'N/A'} to {stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['latest_timestamp'] else 'N/A'}\n\n")
        
        # Add Alert Type Statistics section
        if alert_type_counts:
            f.write("## Alert Type Statistics\n\n")
            f.write("This section provides a breakdown of detected security alerts by type.\n\n")
            
            f.write("| Alert Type | Count | Description |\n")
            f.write("|------------|-------|-------------|\n")
            
            # Define descriptions for each alert type
            alert_descriptions = {
                "Brute-Force Attack": "Multiple failed login attempts from the same source, indicating potential credential brute-forcing",
                "High Privilege Account Usage": "Usage of accounts with elevated privileges (Administrator, root, etc.)",
                "Service Account Abuse": "Interactive login detected for service accounts, which should typically only be used for automated processes",
                "Anomalous Login Time": "Login occurred at an unusual time compared to the user's historical login patterns",
                "Infrequent IP Login": "Login from an IP address that the user rarely or never uses",
                "Impossible Travel": "Rapid login from geographically distant locations, suggesting account compromise",
                "Other Security Event": "Other security-related events detected"
            }
            
            # Sort by count descending
            for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True):
                description = alert_descriptions.get(alert_type, "Security event detected")
                f.write(f"| {alert_type} | {count} | {description} |\n")
            
            f.write("\n")
            
            # Add detailed breakdown for each alert type
            f.write("### Alert Type Breakdown\n\n")
            for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"#### {alert_type} ({count} occurrence{'s' if count != 1 else ''})\n\n")
                f.write(f"**Description:** {alert_descriptions.get(alert_type, 'Security event detected')}\n\n")
                
                if alert_type_details[alert_type]:
                    f.write("**Sample Events:**\n\n")
                    for idx, detail in enumerate(alert_type_details[alert_type][:3], 1):
                        timestamp_str = detail['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if detail['timestamp'] else 'N/A'
                        f.write(f"{idx}. **Time:** {timestamp_str} | **User:** {detail['user'] or 'N/A'} | **IP:** {detail['source_ip'] or 'N/A'}\n")
                        f.write(f"   - {detail['reason']}\n")
                    f.write("\n")
            
            f.write("---\n\n")
        # Add User Baseline Analysis section
        if user_baselines:
            f.write("## User Baseline Analysis\n\n")
            f.write("This section shows the learned behavioral baselines for each user based on historical login patterns.\n\n")
            
            for user, baseline in sorted(user_baselines.items()):
                f.write(f"### User: {user}\n\n")
                f.write(f"- **Total Successful Logins:** {baseline.get('total_logins', 0)}\n")
                
                if baseline.get('login_time_mean') is not None:
                    mean_hour = baseline['login_time_mean']
                    mean_hour_int = int(mean_hour)
                    mean_min = int((mean_hour - mean_hour_int) * 60)
                    std_hour = baseline.get('login_time_std', 0)
                    std_hour_int = int(std_hour)
                    std_min = int((std_hour - std_hour_int) * 60)
                    f.write(f"- **Typical Login Time:** {mean_hour_int:02d}:{mean_min:02d} (Mean: {mean_hour:.2f} hours, Std Dev: {std_hour:.2f} hours)\n")
                else:
                    f.write(f"- **Typical Login Time:** Insufficient data\n")
                
                if baseline.get('last_login_time'):
                    f.write(f"- **Last Login:** {baseline['last_login_time'].strftime('%Y-%m-%d %H:%M:%S')} from {baseline.get('last_login_ip', 'N/A')}\n")
                
                ip_freq_pct = baseline.get('ip_frequency_pct', {})
                if ip_freq_pct:
                    f.write(f"- **Common Source IPs:**\n")
                    # Sort by frequency and show top 5
                    sorted_ips = sorted(ip_freq_pct.items(), key=lambda x: x[1], reverse=True)[:5]
                    for ip, pct in sorted_ips:
                        f.write(f"  - {ip}: {pct*100:.1f}% of logins\n")
                f.write("\n")
        
        f.write("## Risk Events (High & Medium Priority)\n\n")
        
        if not filtered_results:
            f.write("No high or medium risk events detected.\n")
        else:
            f.write("| Risk Level | Time | Affected User | Source IP | Alert Reasons | Raw Log Line |\n")
            f.write("|------------|------|---------------|-----------|---------------|--------------|\n")
            
            for entry in filtered_results:
                risk_level = "HIGH" if entry.risk_score >= 7 else "MEDIUM"
                timestamp_str = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else "N/A"
                user = entry.user or "N/A"
                source_ip = entry.source_ip or "N/A"
                reasons = "; ".join(entry.reasons) if entry.reasons else "N/A"
                raw_line = (entry.raw_line or "N/A")[:100] + "..." if entry.raw_line and len(entry.raw_line) > 100 else (entry.raw_line or "N/A")
                
                # Escape pipe characters in markdown table
                reasons = reasons.replace('|', '\\|')
                raw_line = raw_line.replace('|', '\\|').replace('\n', ' ')
                
                f.write(f"| {risk_level} ({entry.risk_score}) | {timestamp_str} | {user} | {source_ip} | {reasons} | `{raw_line}` |\n")
    
    return output_path


def generate_detailed_report(results: List[LogEntry], stats: Dict[str, Any], user_baselines: Dict[str, Dict[str, Any]] = None, output_path: str = "detailed_analysis.md"):
    """
    Generate a detailed analysis report with all risk events.
    
    Args:
        results: List of LogEntry objects with risk scores
        stats: Statistics dictionary
        user_baselines: User baseline statistics dictionary
        output_path: Path to output markdown file
    """
    # Filter for entries with risk_score > 0
    risk_entries = [entry for entry in results if entry.risk_score > 0]
    risk_entries.sort(key=lambda x: x.risk_score, reverse=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# Security Log Analysis - Detailed Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Analysis Summary\n\n")
        f.write(f"This report presents a comprehensive analysis of security logs. The analysis processed ")
        f.write(f"**{stats['total_log_lines']:,}** log lines, extracting **{stats['total_entries']:,}** security-relevant entries. ")
        f.write(f"The log data spans from **{stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['earliest_timestamp'] else 'N/A'}** ")
        f.write(f"to **{stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['latest_timestamp'] else 'N/A'}**, ")
        f.write(f"covering a time period of **{stats['time_span_hours']:.2f} hours**.\n\n")
        
        f.write("### Key Statistics\n\n")
        f.write(f"- **Total Log Entries Analyzed:** {stats['total_entries']:,}\n")
        f.write(f"- **Total Log Lines Processed:** {stats['total_log_lines']:,}\n")
        f.write(f"- **Time Span:** {stats['time_span_hours']:.2f} hours\n")
        f.write(f"- **Earliest Timestamp:** {stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['earliest_timestamp'] else 'N/A'}\n")
        f.write(f"- **Latest Timestamp:** {stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S') if stats['latest_timestamp'] else 'N/A'}\n")
        f.write(f"- **Total Anomalies Detected:** {stats['anomaly_count']}\n")
        f.write(f"  - High Risk (Score ≥ 7): {stats['high_risk_count']}\n")
        f.write(f"  - Medium Risk (Score 3-6): {stats['medium_risk_count']}\n")
        f.write(f"- **Unique Users:** {stats['unique_user_count']}\n")
        f.write(f"- **Unique Source IPs:** {stats['unique_ip_count']}\n\n")
        
        f.write("### Action Type Distribution\n\n")
        for action_type, count in sorted(stats['action_type_counts'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"- **{action_type}:** {count:,}\n")
        f.write("\n")
        
        # Calculate alert type statistics for detailed report
        alert_type_counts = defaultdict(int)
        alert_type_entries = defaultdict(list)  # Store all entries for each alert type
        
        risk_entries = [entry for entry in results if entry.risk_score > 0]
        for entry in risk_entries:
            if entry.reasons:
                for reason in entry.reasons:
                    # Categorize alert types
                    if "Brute-force" in reason or "brute-force" in reason.lower():
                        alert_type = "Brute-Force Attack"
                    elif "High privilege account" in reason:
                        alert_type = "High Privilege Account Usage"
                    elif "Service account" in reason and "interactive" in reason.lower():
                        alert_type = "Service Account Abuse"
                    elif "Anomalous login time" in reason:
                        alert_type = "Anomalous Login Time"
                    elif "Infrequent IP" in reason:
                        alert_type = "Infrequent IP Login"
                    elif "Impossible travel" in reason:
                        alert_type = "Impossible Travel"
                    else:
                        alert_type = "Other Security Event"
                    
                    alert_type_counts[alert_type] += 1
                    alert_type_entries[alert_type].append(entry)
        
        # Add Alert Type Statistics section
        if alert_type_counts:
            f.write("## Alert Type Statistics and Analysis\n\n")
            f.write("This section provides a comprehensive breakdown of all detected security alerts by type, ")
            f.write("including detailed explanations and examples.\n\n")
            
            f.write("### Alert Type Summary\n\n")
            f.write("| Alert Type | Count | Percentage | Severity |\n")
            f.write("|------------|-------|------------|----------|\n")
            
            total_alerts = sum(alert_type_counts.values())
            alert_severity = {
                "Brute-Force Attack": "High",
                "Impossible Travel": "High",
                "Service Account Abuse": "High",
                "Infrequent IP Login": "Medium",
                "Anomalous Login Time": "Medium",
                "High Privilege Account Usage": "Medium",
                "Other Security Event": "Low"
            }
            
            # Sort by count descending
            for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                severity = alert_severity.get(alert_type, "Medium")
                f.write(f"| {alert_type} | {count} | {percentage:.1f}% | {severity} |\n")
            
            f.write("\n")
            
            # Add detailed analysis for each alert type
            f.write("### Detailed Alert Type Analysis\n\n")
            
            alert_descriptions = {
                "Brute-Force Attack": "Multiple failed login attempts from the same source IP address within a short time window (typically 60 seconds). This indicates an automated attack attempting to guess user credentials. **Risk Score Impact:** +8 points",
                "High Privilege Account Usage": "Detection of login or activity from accounts with elevated system privileges (e.g., Administrator, root). While legitimate, these accounts are high-value targets for attackers. **Risk Score Impact:** +3 points",
                "Service Account Abuse": "Interactive login detected for service accounts that are typically used only for automated processes. This may indicate unauthorized access or misconfiguration. **Risk Score Impact:** +10 points",
                "Anomalous Login Time": "Login occurred at a time significantly outside the user's historical login pattern (beyond 2.5 standard deviations from the mean). This may indicate account compromise or unusual work patterns. **Risk Score Impact:** +4 points",
                "Infrequent IP Login": "Login from an IP address that the user has rarely or never used before (frequency < 5% of historical logins). This may indicate account sharing or compromise. **Risk Score Impact:** +5 points",
                "Impossible Travel": "Rapid login from geographically distant locations within a short time window (e.g., less than 1 hour). This strongly suggests account compromise or credential sharing. **Risk Score Impact:** +7 points",
                "Other Security Event": "Other security-related events that do not fit into the above categories. **Risk Score Impact:** Varies"
            }
            
            for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"#### {alert_type}\n\n")
                f.write(f"**Occurrences:** {count} ({count / total_alerts * 100:.1f}% of all alerts)\n\n")
                f.write(f"**Description:** {alert_descriptions.get(alert_type, 'Security event detected')}\n\n")
                
                # Show unique users and IPs affected
                unique_users = set()
                unique_ips = set()
                for entry in alert_type_entries[alert_type]:
                    if entry.user:
                        unique_users.add(entry.user)
                    if entry.source_ip:
                        unique_ips.add(entry.source_ip)
                
                if unique_users:
                    f.write(f"**Affected Users:** {len(unique_users)} unique user(s) - {', '.join(sorted(unique_users)[:10])}")
                    if len(unique_users) > 10:
                        f.write(f" (and {len(unique_users) - 10} more)")
                    f.write("\n\n")
                
                if unique_ips:
                    f.write(f"**Source IPs:** {len(unique_ips)} unique IP(s) - {', '.join(sorted(unique_ips)[:10])}")
                    if len(unique_ips) > 10:
                        f.write(f" (and {len(unique_ips) - 10} more)")
                    f.write("\n\n")
                
                # Show time range
                timestamps = [entry.timestamp for entry in alert_type_entries[alert_type] if entry.timestamp]
                if timestamps:
                    earliest = min(timestamps)
                    latest = max(timestamps)
                    f.write(f"**Time Range:** {earliest.strftime('%Y-%m-%d %H:%M:%S')} to {latest.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("---\n\n")
        
        # Add User Baseline Analysis section
        if user_baselines:
            f.write("## User Baseline Learning Analysis\n\n")
            f.write("This section presents the behavioral baselines learned for each user through statistical analysis of historical login patterns. ")
            f.write("These baselines are used to detect anomalous behavior such as unusual login times or infrequent source IPs.\n\n")
            
            for user, baseline in sorted(user_baselines.items()):
                f.write(f"### User: {user}\n\n")
                
                f.write(f"#### Login Statistics\n\n")
                f.write(f"- **Total Successful Logins:** {baseline.get('total_logins', 0)}\n")
                
                if baseline.get('login_time_mean') is not None:
                    mean_hour = baseline['login_time_mean']
                    mean_hour_int = int(mean_hour)
                    mean_min = int((mean_hour - mean_hour_int) * 60)
                    std_hour = baseline.get('login_time_std', 0)
                    std_hour_int = int(std_hour)
                    std_min = int((std_hour - std_hour_int) * 60)
                    f.write(f"- **Average Login Time:** {mean_hour_int:02d}:{mean_min:02d} ({mean_hour:.2f} hours since midnight)\n")
                    f.write(f"- **Login Time Standard Deviation:** {std_hour:.2f} hours ({std_hour_int:02d}:{std_min:02d})\n")
                    f.write(f"- **Normal Login Time Range:** {int(mean_hour - std_hour):02d}:{int((mean_hour - std_hour - int(mean_hour - std_hour)) * 60):02d} to {int(mean_hour + std_hour):02d}:{int((mean_hour + std_hour - int(mean_hour + std_hour)) * 60):02d}\n")
                else:
                    f.write(f"- **Average Login Time:** Insufficient data (less than 1 login)\n")
                
                if baseline.get('last_login_time'):
                    f.write(f"- **Most Recent Login:** {baseline['last_login_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"- **Most Recent Login IP:** {baseline.get('last_login_ip', 'N/A')}\n")
                
                ip_freq = baseline.get('ip_frequency', {})
                ip_freq_pct = baseline.get('ip_frequency_pct', {})
                if ip_freq_pct:
                    f.write(f"\n#### Source IP Frequency Analysis\n\n")
                    f.write(f"The following table shows the frequency of source IP addresses used by this user:\n\n")
                    f.write("| Source IP | Login Count | Frequency |\n")
                    f.write("|-----------|-------------|-----------|\n")
                    # Sort by frequency and show all
                    sorted_ips = sorted(ip_freq_pct.items(), key=lambda x: x[1], reverse=True)
                    for ip, pct in sorted_ips:
                        count = ip_freq.get(ip, 0)
                        f.write(f"| {ip} | {count} | {pct*100:.1f}% |\n")
                    f.write("\n")
                    
                    # Identify common vs infrequent IPs
                    common_ips = [ip for ip, pct in ip_freq_pct.items() if pct >= 0.1]  # >= 10%
                    infrequent_ips = [ip for ip, pct in ip_freq_pct.items() if pct < 0.1 and pct >= 0.05]  # 5-10%
                    rare_ips = [ip for ip, pct in ip_freq_pct.items() if pct < 0.05]  # < 5%
                    
                    if common_ips:
                        f.write(f"- **Common IPs (≥10%):** {', '.join(common_ips)}\n")
                    if infrequent_ips:
                        f.write(f"- **Infrequent IPs (5-10%):** {', '.join(infrequent_ips)}\n")
                    if rare_ips:
                        f.write(f"- **Rare IPs (<5%):** {', '.join(rare_ips)} - *Logins from these IPs may trigger infrequent IP alerts*\n")
                    f.write("\n")
                else:
                    f.write(f"\n#### Source IP Frequency Analysis\n\n")
                    f.write("No source IP data available.\n\n")
                
                f.write("---\n\n")
        
        f.write("## Detailed Risk Analysis\n\n")
        
        if not risk_entries:
            f.write("No risk events detected. All analyzed log entries appear normal.\n")
        else:
            f.write(f"Found **{len(risk_entries)}** log entries with risk scores greater than zero, sorted by risk score (highest first):\n\n")
            
            for idx, entry in enumerate(risk_entries, 1):
                f.write(f"### Risk Event #{idx}\n\n")
                f.write(f"- **Risk Score:** {entry.risk_score}\n")
                f.write(f"- **Timestamp:** {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else 'N/A'}\n")
                f.write(f"- **User:** {entry.user or 'N/A'}\n")
                f.write(f"- **Source IP:** {entry.source_ip or 'N/A'}\n")
                f.write(f"- **Action Type:** {entry.action_type or 'N/A'}\n")
                f.write(f"- **Log Source:** {entry.log_source or 'N/A'}\n")
                
                if entry.reasons:
                    f.write(f"- **Risk Reasons:**\n")
                    for reason in entry.reasons:
                        f.write(f"  - {reason}\n")
                
                if entry.raw_line:
                    f.write(f"- **Raw Log Line:**\n")
                    f.write(f"  ```\n")
                    f.write(f"  {entry.raw_line}\n")
                    f.write(f"  ```\n")
                
                f.write("\n")
    
    return output_path


def markdown_to_html(markdown_file: str, html_file: str = None) -> str:
    """
    Convert a Markdown report file to HTML format with styling.
    Uses a simple custom converter for basic Markdown features.
    
    Args:
        markdown_file: Path to the Markdown file
        html_file: Path to output HTML file (default: same name with .html extension)
        
    Returns:
        Path to the generated HTML file
    """
    if html_file is None:
        html_file = markdown_file.replace('.md', '.html')
    
    # Read markdown content
    try:
        with open(markdown_file, 'r', encoding='utf-8') as f:
            md_lines = f.readlines()
    except Exception as e:
        print(f"Error reading markdown file {markdown_file}: {e}")
        return html_file
    
    # Helper function to process markdown inline elements
    def process_markdown_line(text: str) -> str:
        """Process inline markdown elements in a line."""
        if not text.strip():
            return ''
        # Escape HTML first
        text = html_module.escape(text)
        # Bold
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        # Code spans
        text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
        return text
    
    # Simple Markdown to HTML converter
    html_lines = []
    in_code_block = False
    in_table = False
    in_list = False
    table_is_header = True
    
    i = 0
    while i < len(md_lines):
        line = md_lines[i].rstrip()
        next_line = md_lines[i + 1].rstrip() if i + 1 < len(md_lines) else ''
        
        # Code blocks
        if line.startswith('```'):
            if not in_code_block:
                html_lines.append('<pre><code>')
                in_code_block = True
            else:
                html_lines.append('</code></pre>')
                in_code_block = False
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            i += 1
            continue
        
        if in_code_block:
            html_lines.append(html_module.escape(line))
            i += 1
            continue
        
        # Headers
        if line.startswith('# '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            html_lines.append(f'<h1>{process_markdown_line(line[2:])}</h1>')
        elif line.startswith('## '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            html_lines.append(f'<h2>{process_markdown_line(line[3:])}</h2>')
        elif line.startswith('### '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            html_lines.append(f'<h3>{process_markdown_line(line[4:])}</h3>')
        elif line.startswith('#### '):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            html_lines.append(f'<h4>{process_markdown_line(line[5:])}</h4>')
        # Tables
        elif '|' in line:
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if line.startswith('|---'):
                # Table separator - mark next row as data
                table_is_header = False
            else:
                if not in_table:
                    html_lines.append('<table>')
                    in_table = True
                    table_is_header = True
                
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                if cells:
                    tag = 'th' if table_is_header else 'td'
                    html_lines.append('<tr>')
                    for cell in cells:
                        cell_html = process_markdown_line(cell)
                        html_lines.append(f'<{tag}>{cell_html}</{tag}>')
                    html_lines.append('</tr>')
                    table_is_header = False
        # Horizontal rule (not table separator)
        elif line == '---' and not in_table:
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if in_table:
                html_lines.append('</table>')
                in_table = False
            html_lines.append('<hr>')
        # Lists
        elif line.startswith('- ') or line.startswith('* '):
            if in_table:
                html_lines.append('</table>')
                in_table = False
            if not in_list:
                html_lines.append('<ul>')
                in_list = True
            content = process_markdown_line(line[2:])
            html_lines.append(f'<li>{content}</li>')
        # Empty line
        elif not line.strip():
            if in_table:
                html_lines.append('</table>')
                in_table = False
                table_is_header = True
            elif in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append('<br>')
        # Regular paragraph
        else:
            if in_table:
                html_lines.append('</table>')
                in_table = False
                table_is_header = True
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            processed = process_markdown_line(line)
            if processed:
                html_lines.append(f'<p>{processed}</p>')
        
        i += 1
    
    if in_table:
        html_lines.append('</table>')
    if in_list:
        html_lines.append('</ul>')
    
    html_content = '\n'.join(html_lines)
    
    # Create styled HTML document
    html_template = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Log Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        h2 {{
            color: #34495e;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 8px;
            margin-top: 30px;
        }}
        h3 {{
            color: #555;
            margin-top: 25px;
        }}
        h4 {{
            color: #666;
            margin-top: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        tr:nth-child(even) {{
            background-color: #fafafa;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        pre {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            line-height: 1.4;
        }}
        pre code {{
            background-color: transparent;
            color: inherit;
            padding: 0;
        }}
        ul, ol {{
            margin: 10px 0;
            padding-left: 30px;
        }}
        li {{
            margin: 5px 0;
        }}
        strong {{
            color: #2c3e50;
            font-weight: 600;
        }}
        .risk-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .risk-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .risk-low {{
            color: #27ae60;
        }}
        hr {{
            border: none;
            border-top: 2px solid #ecf0f1;
            margin: 30px 0;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 0.9em;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_content}
        <div class="footer">
            <p>Generated by Security Log Analyzer | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
    
    # Write HTML file
    try:
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        return html_file
    except Exception as e:
        print(f"Error writing HTML file {html_file}: {e}")
        return html_file


def print_introduction(config: Dict[str, Any], log_file: str, num_processes: int):
    """
    Print system introduction, configuration, and current analysis parameters.
    
    Args:
        config: Configuration dictionary
        log_file: Path to the log file being analyzed
        num_processes: Number of parallel processes
    """
    print("=" * 70)
    print("SECURITY LOG ANALYZER")
    print("=" * 70)
    print("Professional Security Log Analysis Tool")
    print("Supports: Windows Event Logs (.evtx) | Linux Syslog")
    print("=" * 70)
    print()
    print("Configuration:")
    print(f"  High Privilege Accounts: {config.get('HIGH_PRIVILEGE_ACCOUNTS', [])}")
    print(f"  Known Service Accounts: {config.get('KNOWN_SERVICE_ACCOUNTS', [])}")
    print(f"  High Risk IPs: {len(config.get('HIGH_RISK_IPS', []))} configured")
    print(f"  Brute Force Rate Threshold: {config.get('BRUTE_FORCE_RATE_THRESHOLD', 5)} failures/60s")
    print(f"  Time Anomaly Std Multiplier: {config.get('TIME_ANOMALY_STD_MULTIPLIER', 2.5)}")
    print(f"  Infrequent IP Threshold: {config.get('INFREQUENT_IP_THRESHOLD', 0.05)}")
    print(f"  Impossible Travel Min Seconds: {config.get('IMPOSSIBLE_TRAVEL_MIN_SECONDS', 3600)}s")
    print()
    print("Analysis Parameters:")
    print(f"  Log File: {log_file}")
    print(f"  Parallel Processes: {num_processes}")
    print(f"  File Size: {os.path.getsize(log_file) / (1024*1024):.2f} MB")
    print()
    print("=" * 70)
    print()


def main():
    """Main entry point for the security log analyzer."""
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Analyze Windows (.evtx) and Linux (syslog) security logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_log_analyzer.py -f security.evtx
  python security_log_analyzer.py --log-file /var/log/auth.log --processes 8
        """
    )
    
    parser.add_argument(
        '-f', '--log-file',
        required=True,
        type=str,
        help='Path to the log file to analyze (Windows .evtx or Linux syslog)'
    )
    
    parser.add_argument(
        '-p', '--processes',
        type=int,
        default=4,
        help='Number of parallel processes for log analysis (default: 4)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    args = parser.parse_args()
    
    # Validate log file exists
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found.")
        sys.exit(1)
    
    # Validate processes count
    if args.processes < 1:
        print("Error: Number of processes must be at least 1.")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Print introduction
    print_introduction(config, args.log_file, args.processes)
    
    # Start timing
    start_time = time.time()
    
    # Parse log file
    print("Starting log analysis...")
    print()
    
    try:
        # Phase 1: Parse logs
        entries = parse_log(args.log_file, args.processes)
        print()
        print(f"Parsed {len(entries)} log entries.")
        
        if len(entries) == 0:
            file_ext = Path(args.log_file).suffix.lower()
            print("=" * 70)
            print("WARNING: No log entries were parsed.")
            print("=" * 70)
            print("Possible reasons:")
            print("  1. Log file format not recognized")
            print("  2. No security-relevant events found in the file")
            print("  3. Log file is empty or corrupted")
            if file_ext == '.evtx':
                print("  4. EVTX file may not contain security events (Event IDs 4624, 4625, etc.)")
            print()
            print("Please check:")
            print(f"  - File path: {args.log_file}")
            if file_ext == '.evtx':
                print("  - EVTX file contains Windows Security events")
                print("  - File is a valid Windows Event Log export")
            else:
                print("  - File format matches expected syslog format")
                print("  - File contains authentication/login events")
            print("=" * 70)
            sys.exit(0)
        
        # Phase 2: Calculate baselines
        print("Calculating user baselines...")
        user_baselines = calculate_baselines(entries, config)
        print(f"Built baselines for {len(user_baselines)} users.")
        
        # Phase 3: Detect anomalies
        print("Detecting anomalies and calculating risk scores...")
        failure_counts = defaultdict(list)
        user_last_login = {}  # Runtime state for impossible travel detection
        analyzed_entries = []
        
        with tqdm.tqdm(total=len(entries), desc="Analyzing entries", unit="entry") as pbar:
            for entry in entries:
                analyzed_entry = detect_anomalies(entry, user_baselines, config, failure_counts, user_last_login)
                analyzed_entries.append(analyzed_entry)
                pbar.update(1)
        
        # Count entries with risk
        risk_count = sum(1 for entry in analyzed_entries if entry.risk_score > 0)
        print(f"\nDetected {risk_count} entries with risk scores > 0.")
        
        # Phase 4: Calculate statistics
        print("Calculating statistics...")
        stats = calculate_statistics(analyzed_entries, args.log_file)
        
        # Phase 5: Generate reports
        print("Generating reports...")
        brief_report_path = generate_brief_report(analyzed_entries, stats, user_baselines)
        detailed_report_path = generate_detailed_report(analyzed_entries, stats, user_baselines)
        
        # Generate HTML versions
        print("Generating HTML reports...")
        brief_html_path = markdown_to_html(brief_report_path)
        detailed_html_path = markdown_to_html(detailed_report_path)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Print summary
        print()
        print("=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)
        print(f"Total Processing Time: {elapsed_time:.2f} seconds")
        print()
        print("Statistics:")
        print(f"  Total Entries Analyzed: {stats['total_entries']:,}")
        print(f"  Total Log Lines: {stats['total_log_lines']:,}")
        print(f"  Time Span: {stats['time_span_hours']:.2f} hours")
        print(f"  Anomalies Detected: {stats['anomaly_count']}")
        print(f"    - High Risk (≥7): {stats['high_risk_count']}")
        print(f"    - Medium Risk (3-6): {stats['medium_risk_count']}")
        print(f"  Unique Users: {stats['unique_user_count']}")
        print(f"  Unique IPs: {stats['unique_ip_count']}")
        print()
        print("Reports Generated:")
        try:
            print(f"  [Brief Report]: {os.path.abspath(brief_report_path)}")
            print(f"  [Brief Report HTML]: {os.path.abspath(brief_html_path)}")
            print(f"  [Detailed Report]: {os.path.abspath(detailed_report_path)}")
            print(f"  [Detailed Report HTML]: {os.path.abspath(detailed_html_path)}")
        except UnicodeEncodeError:
            # Fallback for Windows console encoding issues
            print(f"  Brief Report: {os.path.abspath(brief_report_path)}")
            print(f"  Brief Report HTML: {os.path.abspath(brief_html_path)}")
            print(f"  Detailed Report: {os.path.abspath(detailed_report_path)}")
            print(f"  Detailed Report HTML: {os.path.abspath(detailed_html_path)}")
        print()
        print("=" * 70)
        
    except Exception as e:
        print(f"\nError during log analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

