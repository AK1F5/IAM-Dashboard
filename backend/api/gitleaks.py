"""
Gitleaks API Resource
Provides secret scanning functionality using Gitleaks
"""

import subprocess
import json
import os
import logging
from datetime import datetime
from flask_restful import Resource, reqparse

logger = logging.getLogger(__name__)

class GitleaksResource(Resource):
    def post(self):
        """Run Gitleaks scan on specified repository"""
        parser = reqparse.RequestParser()
        parser.add_argument('repoPath', type=str, default='/workspace', help='Repository path to scan')
        parser.add_argument('scanMode', type=str, default='dir', help='Scan mode: dir, git, staged, commit')
        parser.add_argument('commitHash', type=str, help='Specific commit hash for commit scan mode')
        parser.add_argument('maxDecodeDepth', type=int, default=0, help='Maximum decode depth for encoded secrets')
        parser.add_argument('maxArchiveDepth', type=int, default=0, help='Maximum archive extraction depth')
        args = parser.parse_args()
        
        try:
            logger.info(f"Starting Gitleaks scan: {args['scanMode']} on {args['repoPath']}")
            
            # Build Gitleaks command
            cmd = ['gitleaks', 'detect']
            
            # Add source path
            cmd.extend(['--source', args['repoPath']])
            
            # Add scan mode specific options
            if args['scanMode'] == 'staged':
                cmd.append('--staged')
            elif args['scanMode'] == 'commit' and args['commitHash']:
                cmd.extend(['--commit', args['commitHash']])
            elif args['scanMode'] == 'dir':
                cmd.append('--no-git')
            
            # Add advanced options
            if args['maxDecodeDepth'] > 0:
                cmd.extend(['--max-decode-depth', str(args['maxDecodeDepth'])])
            
            if args['maxArchiveDepth'] > 0:
                cmd.extend(['--max-archive-depth', str(args['maxArchiveDepth'])])
            
            # Add output options
            cmd.extend([
                '--report-format', 'json',
                '--report-path', '/tmp/gitleaks-results.json',
                '--verbose'
            ])
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            # Run Gitleaks scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Check if scan was successful
            if result.returncode not in [0, 1]:  # 0 = no leaks, 1 = leaks found
                logger.error(f"Gitleaks scan failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                return {'error': f'Gitleaks scan failed: {result.stderr}'}, 500
            
            # Read results
            findings = []
            if os.path.exists('/tmp/gitleaks-results.json'):
                try:
                    with open('/tmp/gitleaks-results.json', 'r') as f:
                        findings = json.load(f)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Gitleaks results: {e}")
                    return {'error': 'Failed to parse scan results'}, 500
            
            # Process results
            processed_findings = []
            for finding in findings:
                processed_findings.append({
                    'id': f"gitleaks-{hash(finding.get('file', '') + str(finding.get('line', 0)))}",
                    'rule_id': finding.get('ruleID', ''),
                    'file': finding.get('file', ''),
                    'line': finding.get('line', 0),
                    'column': finding.get('column', 0),
                    'secret': finding.get('secret', ''),
                    'severity': self._determine_severity(finding.get('ruleID', '')),
                    'rule_name': finding.get('rule', ''),
                    'description': finding.get('description', ''),
                    'recommendation': self._get_recommendation(finding.get('ruleID', '')),
                    'tags': finding.get('tags', []),
                    'entropy': finding.get('entropy', 0),
                    'commit_hash': finding.get('commit', ''),
                    'author': finding.get('author', ''),
                    'commit_date': finding.get('date', ''),
                    'risk_score': self._calculate_risk_score(finding)
                })
            
            # Calculate scan summary
            scan_summary = {
                'total_secrets': len(processed_findings),
                'critical_findings': len([f for f in processed_findings if f['severity'] == 'Critical']),
                'high_findings': len([f for f in processed_findings if f['severity'] == 'High']),
                'medium_findings': len([f for f in processed_findings if f['severity'] == 'Medium']),
                'low_findings': len([f for f in processed_findings if f['severity'] == 'Low']),
                'files_with_secrets': len(set(f['file'] for f in processed_findings)),
                'unique_secret_types': len(set(f['rule_id'] for f in processed_findings))
            }
            
            logger.info(f"Gitleaks scan completed: {scan_summary['total_secrets']} secrets found")
            
            return {
                'scan_id': f"gitleaks-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'status': 'Completed',
                'progress': 100,
                'repository_path': args['repoPath'],
                'scan_mode': args['scanMode'],
                'total_files_scanned': self._count_files_scanned(args['repoPath']),
                'findings': processed_findings,
                'scan_summary': scan_summary,
                'started_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat(),
                'gitleaks_version': self._get_gitleaks_version(),
                'scan_duration': 'N/A'  # Could be calculated if needed
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Gitleaks scan timeout")
            return {'error': 'Scan timeout - scan took longer than 5 minutes'}, 408
        except Exception as e:
            logger.error(f"Gitleaks scan error: {str(e)}")
            return {'error': f'Scan failed: {str(e)}'}, 500
    
    def get(self):
        """Get Gitleaks version and configuration info"""
        try:
            version = self._get_gitleaks_version()
            return {
                'gitleaks_version': version,
                'available_scan_modes': ['dir', 'git', 'staged', 'commit'],
                'supported_features': [
                    'secret_detection',
                    'entropy_analysis',
                    'rule_based_detection',
                    'archive_scanning',
                    'decoding_support'
                ]
            }
        except Exception as e:
            return {'error': f'Failed to get Gitleaks info: {str(e)}'}, 500
    
    def _determine_severity(self, rule_id):
        """Determine severity based on rule ID"""
        critical_rules = [
            'github-pat', 'aws-access-key', 'private-key', 'ssh-private-key',
            'slack-token', 'stripe-api-key', 'paypal-client-secret'
        ]
        high_rules = [
            'generic-api-key', 'slack-webhook', 'database-url', 'mongodb-uri',
            'postgresql-uri', 'mysql-uri', 'redis-uri'
        ]
        medium_rules = [
            'generic-secret', 'jwt-token', 'api-key', 'access-token'
        ]
        
        if rule_id in critical_rules:
            return 'Critical'
        elif rule_id in high_rules:
            return 'High'
        elif rule_id in medium_rules:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_recommendation(self, rule_id):
        """Get remediation recommendation based on rule ID"""
        recommendations = {
            'github-pat': 'Remove the GitHub Personal Access Token and use environment variables or GitHub Apps for authentication',
            'aws-access-key': 'Remove AWS Access Key ID and use IAM roles instead of hardcoded credentials',
            'private-key': 'Store private keys in secure key management systems like AWS KMS, Azure Key Vault, or HashiCorp Vault',
            'ssh-private-key': 'Store SSH private keys in secure key management systems and use SSH agent forwarding',
            'slack-token': 'Regenerate the Slack token and store it in environment variables or secret management',
            'stripe-api-key': 'Regenerate the Stripe API key and store it securely in environment variables',
            'paypal-client-secret': 'Regenerate the PayPal client secret and store it in secure environment variables',
            'generic-api-key': 'Move API keys to environment variables or secret management systems',
            'database-url': 'Use connection pooling and store database credentials in environment variables',
            'mongodb-uri': 'Store MongoDB connection string in environment variables',
            'postgresql-uri': 'Store PostgreSQL connection string in environment variables',
            'mysql-uri': 'Store MySQL connection string in environment variables',
            'redis-uri': 'Store Redis connection string in environment variables',
            'slack-webhook': 'Store Slack webhook URLs in environment variables',
            'generic-secret': 'Remove the secret and use secure alternatives like environment variables',
            'jwt-token': 'Use proper JWT token management and store secrets securely',
            'api-key': 'Store API keys in environment variables or secret management systems',
            'access-token': 'Use proper token management and store access tokens securely'
        }
        return recommendations.get(rule_id, 'Remove the secret and use secure alternatives like environment variables or secret management systems')
    
    def _calculate_risk_score(self, finding):
        """Calculate risk score based on finding properties"""
        base_score = 30
        entropy = finding.get('entropy', 0)
        rule_id = finding.get('ruleID', '')
        
        # Adjust base score based on rule type
        if rule_id in ['github-pat', 'aws-access-key', 'private-key']:
            base_score = 80
        elif rule_id in ['generic-api-key', 'database-url', 'slack-webhook']:
            base_score = 60
        elif rule_id in ['generic-secret', 'api-key']:
            base_score = 40
        
        # Add entropy factor
        entropy_factor = min(entropy * 5, 20)
        
        return min(100, base_score + entropy_factor)
    
    def _count_files_scanned(self, path):
        """Count files in the scanned directory"""
        try:
            result = subprocess.run(['find', path, '-type', 'f'], capture_output=True, text=True, timeout=30)
            return len(result.stdout.splitlines())
        except:
            return 0
    
    def _get_gitleaks_version(self):
        """Get Gitleaks version"""
        try:
            result = subprocess.run(['gitleaks', 'version'], capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except:
            return 'Unknown'
