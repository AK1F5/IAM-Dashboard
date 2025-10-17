import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Progress } from "./ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Skeleton } from "./ui/skeleton";
import { Alert, AlertDescription } from "./ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { 
  Play, 
  Square, 
  Settings2, 
  AlertTriangle, 
  RefreshCw,
  Shield,
  Lock,
  FileText
} from "lucide-react";
import { toast } from "sonner@2.0.3";
import { DemoModeBanner } from "./DemoModeBanner";

interface GitleaksFinding {
  id: string;
  rule_id: string;
  file: string;
  line: number;
  column: number;
  secret: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  rule_name: string;
  description: string;
  recommendation: string;
  tags: string[];
  entropy?: number;
  commit_hash?: string;
  author?: string;
  commit_date?: string;
  risk_score: number;
}

interface GitleaksScanResult {
  scan_id: string;
  status: 'Running' | 'Completed' | 'Failed';
  progress: number;
  repository_path: string;
  scan_mode: string;
  total_files_scanned: number;
  findings: GitleaksFinding[];
  scan_summary: {
    total_secrets: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    files_with_secrets: number;
    unique_secret_types: number;
  };
  started_at?: string;
  completed_at?: string;
}

// Mock Gitleaks findings
const mockGitleaksFindings: GitleaksFinding[] = [
  {
    id: 'gitleaks-finding-001',
    rule_id: 'github-pat',
    file: 'config/secrets.env',
    line: 15,
    column: 8,
    secret: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    severity: 'Critical',
    rule_name: 'GitHub Personal Access Token',
    description: 'GitHub Personal Access Token found in configuration file',
    recommendation: 'Remove the token from the file and use environment variables or secret management',
    tags: ['github', 'api-key', 'token'],
    entropy: 4.2,
    commit_hash: 'a1b2c3d4e5f6',
    author: 'developer@company.com',
    commit_date: '2024-09-15T10:00:00Z',
    risk_score: 95
  },
  {
    id: 'gitleaks-finding-002',
    rule_id: 'aws-access-key',
    file: 'src/config/aws.js',
    line: 8,
    column: 12,
    secret: 'AKIAIOSFODNN7EXAMPLE',
    severity: 'High',
    rule_name: 'AWS Access Key',
    description: 'AWS Access Key ID found in source code',
    recommendation: 'Use IAM roles or environment variables instead of hardcoded credentials',
    tags: ['aws', 'access-key', 'credentials'],
    entropy: 3.8,
    commit_hash: 'b2c3d4e5f6g7',
    author: 'dev@company.com',
    commit_date: '2024-09-14T15:30:00Z',
    risk_score: 88
  },
  {
    id: 'gitleaks-finding-003',
    rule_id: 'generic-api-key',
    file: 'api/keys.json',
    line: 3,
    column: 15,
    secret: 'sk_live_51234567890abcdef',
    severity: 'High',
    rule_name: 'Generic API Key',
    description: 'Generic API key detected in configuration file',
    recommendation: 'Move API keys to secure environment variables or secret management system',
    tags: ['api-key', 'generic'],
    entropy: 4.1,
    commit_hash: 'c3d4e5f6g7h8',
    author: 'admin@company.com',
    commit_date: '2024-09-13T11:20:00Z',
    risk_score: 82
  },
  {
    id: 'gitleaks-finding-004',
    rule_id: 'database-url',
    file: 'database/config.py',
    line: 22,
    column: 5,
    secret: 'postgresql://user:password123@localhost:5432/mydb',
    severity: 'Medium',
    rule_name: 'Database Connection String',
    description: 'Database connection string with credentials found',
    recommendation: 'Use connection pooling and environment variables for database credentials',
    tags: ['database', 'postgresql', 'connection'],
    entropy: 3.2,
    commit_hash: 'd4e5f6g7h8i9',
    author: 'dba@company.com',
    commit_date: '2024-09-12T09:45:00Z',
    risk_score: 65
  },
  {
    id: 'gitleaks-finding-005',
    rule_id: 'slack-webhook',
    file: 'notifications/slack.py',
    line: 7,
    column: 20,
    secret: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    severity: 'Low',
    rule_name: 'Slack Webhook URL',
    description: 'Slack webhook URL found in notification configuration',
    recommendation: 'Store webhook URLs in environment variables or secure configuration',
    tags: ['slack', 'webhook', 'notification'],
    entropy: 2.8,
    commit_hash: 'e5f6g7h8i9j0',
    author: 'ops@company.com',
    commit_date: '2024-09-11T14:15:00Z',
    risk_score: 35
  }
];

const mockGitleaksScanResult: GitleaksScanResult = {
  scan_id: 'gitleaks-scan-demo-789',
  status: 'Completed',
  progress: 100,
  repository_path: '/workspace',
  scan_mode: 'full',
  total_files_scanned: 1247,
  findings: mockGitleaksFindings,
  scan_summary: {
    total_secrets: 5,
    critical_findings: 1,
    high_findings: 2,
    medium_findings: 1,
    low_findings: 1,
    files_with_secrets: 5,
    unique_secret_types: 5
  },
  started_at: new Date(Date.now() - 300000).toISOString(),
  completed_at: new Date(Date.now() - 240000).toISOString()
};

export function GitleaksSecurity() {
  const [scanResult, setScanResult] = useState<GitleaksScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [repositoryPath, setRepositoryPath] = useState('/workspace');
  const [scanMode, setScanMode] = useState('dir');
  const [loading, setLoading] = useState(false);
  const [gitleaksInfo, setGitleaksInfo] = useState<any>(null);

  useEffect(() => {
    // Load Gitleaks info on component mount
    const loadGitleaksInfo = async () => {
      try {
        const response = await fetch('/api/v1/gitleaks');
        if (response.ok) {
          const info = await response.json();
          setGitleaksInfo(info);
        }
      } catch (err) {
        console.warn('Failed to load Gitleaks info:', err);
      }
    };
    
    loadGitleaksInfo();
  }, []);

  useEffect(() => {
    if (scanResult?.status === 'Completed') {
      toast.success('Gitleaks scan completed!', {
        description: `Found ${scanResult.scan_summary.total_secrets} secrets across ${scanResult.scan_summary.files_with_secrets} files`
      });
    } else if (scanResult?.status === 'Failed') {
      toast.error('Gitleaks scan failed', {
        description: 'Check repository path and permissions'
      });
    }
  }, [scanResult?.status]);

  const handleStartScan = async () => {
    setIsScanning(true);
    setError(null);
    
    try {
      toast.info('Gitleaks scan started', {
        description: 'Scanning repository for secrets and sensitive data...'
      });

      // Call real Gitleaks API
      const response = await fetch('/api/v1/gitleaks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repoPath: repositoryPath,
          scanMode: scanMode,
          maxDecodeDepth: 2, // Enable decoding for better secret detection
          maxArchiveDepth: 1 // Enable archive scanning
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      setScanResult(result);
      setIsScanning(false);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      setIsScanning(false);
      toast.error('Failed to start Gitleaks scan', {
        description: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  };

  const handleStopScan = async () => {
    try {
      setIsScanning(false);
      if (scanResult) {
        setScanResult({ ...scanResult, status: 'Failed' });
      }
      toast.warning('Gitleaks scan stopped', {
        description: 'Secret scan was interrupted'
      });
    } catch (err) {
      toast.error('Failed to stop scan');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-[#ff0040] text-white';
      case 'High': return 'bg-[#ff6b35] text-white';
      case 'Medium': return 'bg-[#ffb000] text-black';
      case 'Low': return 'bg-[#00ff88] text-black';
      default: return 'bg-gray-500 text-white';
    }
  };

  return (
    <div className="p-6 space-y-6">
      <DemoModeBanner />
      
      {/* Gitleaks Info */}
      {gitleaksInfo && (
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-primary" />
              Gitleaks Scanner Info
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Version</p>
                <p className="font-mono text-sm">{gitleaksInfo.gitleaks_version}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Available Scan Modes</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {gitleaksInfo.available_scan_modes?.map((mode: string) => (
                    <Badge key={mode} variant="outline" className="text-xs">
                      {mode}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* EC2 Scan Configuration -- change to gitleaks */}
      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-primary" />
            Gitleaks Secret Detection Scan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-4">
              <div>
                <Label htmlFor="repo-path">Repository Path</Label>
                <Input 
                  id="repo-path"
                  placeholder="/path/to/repository"
                  className="bg-input border-border"
                  value={repositoryPath}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setRepositoryPath(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="scan-mode">Scan Mode</Label>
                <Select value={scanMode} onValueChange={setScanMode}>
                  <SelectTrigger className="bg-input border-border">
                    <SelectValue placeholder="Select scan mode" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="dir">Directory Scan (No Git)</SelectItem>
                    <SelectItem value="git">Git History Scan</SelectItem>
                    <SelectItem value="staged">Staged Files Only</SelectItem>
                    <SelectItem value="commit">Specific Commit</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <Label>Detection Rules</Label>
                <div className="space-y-2 mt-2">
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">API Keys & Tokens</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">Database Credentials</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">Private Keys</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">Cloud Provider Keys</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" className="rounded" />
                    <span className="text-sm">Generic Secrets</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <Label>Output Options</Label>
                <div className="space-y-2 mt-2">
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">JSON Report</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">CSV Export</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" className="rounded" />
                    <span className="text-sm">Detailed Logs</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span className="text-sm">Redacted Secrets</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
          
          <div className="flex gap-4">
            <Button 
              onClick={handleStartScan}
              disabled={isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/80 cyber-glow"
            >
              <Play className="h-4 w-4 mr-2" />
              {isScanning ? "Scanning..." : "Start Scan"}
            </Button>
            
            {isScanning && (
              <Button 
                onClick={handleStopScan}
                variant="destructive"
              >
                <Square className="h-4 w-4 mr-2" />
                Stop Scan
              </Button>
            )}
            
            <Button variant="outline" className="border-border">
              <Settings2 className="h-4 w-4 mr-2" />
              Advanced Settings
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert className="border-destructive bg-destructive/10">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            <strong>Scan Error:</strong> {error}
          </AlertDescription>
        </Alert>
      )}

      {/* Scan Progress */}
      {(isScanning || scanResult) && (
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Gitleaks Secret Scan Progress</span>
              <div className="flex items-center gap-2">
                {scanResult && (
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    onClick={() => setLoading(!loading)}
                    disabled={loading}
                  >
                    <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                  </Button>
                )}
                <Badge 
                  variant={isScanning ? "secondary" : scanResult?.status === "Completed" ? "default" : "destructive"}
                  className={
                    isScanning ? "bg-[#ffb000] text-black" : 
                    scanResult?.status === "Completed" ? "bg-[#00ff88] text-black" : 
                    "bg-[#ff0040] text-white"
                  }
                >
                  {isScanning ? "In Progress" : scanResult?.status || "No Scan"}
                </Badge>
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <Progress 
                value={scanResult?.progress || 0} 
                className="h-3" 
              />
              <div className="flex justify-between text-sm text-muted-foreground">
                <span>
                  {isScanning ? 'Scanning repository for secrets...' : 
                   scanResult ? `Scanned ${scanResult.total_files_scanned} files in ${scanResult.repository_path}` :
                   'Ready to scan'}
                </span>
                <span>{scanResult?.progress || 0}%</span>
              </div>
              
              {scanResult && scanResult.status === 'Completed' && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                  <div className="cyber-glass p-3 rounded-lg text-center">
                    <p className="text-lg font-medium text-[#ff0040]">{scanResult.scan_summary.critical_findings}</p>
                    <p className="text-xs text-muted-foreground">Critical</p>
                  </div>
                  <div className="cyber-glass p-3 rounded-lg text-center">
                    <p className="text-lg font-medium text-[#ff6b35]">{scanResult.scan_summary.high_findings}</p>
                    <p className="text-xs text-muted-foreground">High</p>
                  </div>
                  <div className="cyber-glass p-3 rounded-lg text-center">
                    <p className="text-lg font-medium text-[#ffb000]">{scanResult.scan_summary.medium_findings}</p>
                    <p className="text-xs text-muted-foreground">Medium</p>
                  </div>
                  <div className="cyber-glass p-3 rounded-lg text-center">
                    <p className="text-lg font-medium text-[#00ff88]">{scanResult.scan_summary.low_findings}</p>
                    <p className="text-xs text-muted-foreground">Low</p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Results */}
      {scanResult && scanResult.findings.length > 0 && (
        <Card className="cyber-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-primary" />
              Gitleaks Secret Findings ({scanResult.findings.length} secrets found)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="findings" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="findings">Secret Findings</TabsTrigger>
                <TabsTrigger value="instances">File Overview</TabsTrigger>
                <TabsTrigger value="compliance">Scan Summary</TabsTrigger>
              </TabsList>
              
              <TabsContent value="findings" className="space-y-4">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border">
                      <TableHead>File</TableHead>
                      <TableHead>Secret Type</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Line</TableHead>
                      <TableHead>Risk Score</TableHead>
                      <TableHead>Recommendation</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {loading ? (
                      Array.from({ length: 5 }).map((_, index) => (
                        <TableRow key={index} className="border-border">
                          <TableCell><Skeleton className="h-4 w-32 bg-muted/20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-24 bg-muted/20" /></TableCell>
                          <TableCell><Skeleton className="h-6 w-16 bg-muted/20" /></TableCell>
                          <TableCell><Skeleton className="h-6 w-16 bg-muted/20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-12 bg-muted/20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-48 bg-muted/20" /></TableCell>
                        </TableRow>
                      ))
                    ) : (
                      scanResult.findings.map((finding: GitleaksFinding) => (
                        <TableRow 
                          key={finding.id} 
                          className="border-border cursor-pointer hover:bg-accent/10 transition-colors"
                        >
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <FileText className="h-4 w-4" />
                              <div>
                                <p className="font-mono text-sm">{finding.file}</p>
                                <p className="text-xs text-muted-foreground">Line {finding.line}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div>
                              <p className="font-medium text-sm">{finding.rule_name}</p>
                              <p className="text-xs text-muted-foreground">{finding.description}</p>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(finding.severity)}>
                              {finding.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="border-border">
                              {finding.line}:{finding.column}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className={
                              finding.risk_score > 80 ? "text-[#ff0040]" :
                              finding.risk_score > 60 ? "text-[#ff6b35]" :
                              finding.risk_score > 40 ? "text-[#ffb000]" :
                              "text-[#00ff88]"
                            }>
                              {finding.risk_score}/100
                            </span>
                          </TableCell>
                          <TableCell className="text-sm max-w-xs">
                            {finding.recommendation}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </TabsContent>

              <TabsContent value="instances" className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="cyber-glass p-4 rounded-lg text-center">
                    <FileText className="h-8 w-8 text-primary mx-auto mb-2" />
                    <p className="text-2xl font-medium">{scanResult.scan_summary.files_with_secrets}</p>
                    <p className="text-sm text-muted-foreground">Files with Secrets</p>
                  </div>
                  <div className="cyber-glass p-4 rounded-lg text-center">
                    <Lock className="h-8 w-8 text-primary mx-auto mb-2" />
                    <p className="text-2xl font-medium">{scanResult.scan_summary.total_secrets}</p>
                    <p className="text-sm text-muted-foreground">Total Secrets</p>
                  </div>
                  <div className="cyber-glass p-4 rounded-lg text-center">
                    <Shield className="h-8 w-8 text-primary mx-auto mb-2" />
                    <p className="text-2xl font-medium">{scanResult.scan_summary.unique_secret_types}</p>
                    <p className="text-sm text-muted-foreground">Secret Types</p>
                  </div>
                  <div className="cyber-glass p-4 rounded-lg text-center">
                    <AlertTriangle className="h-8 w-8 text-primary mx-auto mb-2" />
                    <p className="text-2xl font-medium">{scanResult.scan_summary.critical_findings + scanResult.scan_summary.high_findings}</p>
                    <p className="text-sm text-muted-foreground">High Risk</p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="compliance" className="space-y-4">
                <div className="grid gap-4">
                  <div className="cyber-glass p-4 rounded-lg">
                    <h4 className="font-medium mb-4">Scan Summary</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Repository Path:</span>
                        <span className="font-mono text-sm">{scanResult.repository_path}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Scan Mode:</span>
                        <Badge variant="outline">{scanResult.scan_mode}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Files Scanned:</span>
                        <span className="font-medium">{scanResult.total_files_scanned}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Scan Duration:</span>
                        <span className="text-sm">
                          {scanResult.started_at && scanResult.completed_at ? 
                            `${Math.round((new Date(scanResult.completed_at).getTime() - new Date(scanResult.started_at).getTime()) / 1000)}s` : 
                            'N/A'
                          }
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="cyber-glass p-4 rounded-lg">
                    <h4 className="font-medium mb-4">Severity Breakdown</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Critical:</span>
                        <Badge className={getSeverityColor('Critical')}>{scanResult.scan_summary.critical_findings}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">High:</span>
                        <Badge className={getSeverityColor('High')}>{scanResult.scan_summary.high_findings}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Medium:</span>
                        <Badge className={getSeverityColor('Medium')}>{scanResult.scan_summary.medium_findings}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Low:</span>
                        <Badge className={getSeverityColor('Low')}>{scanResult.scan_summary.low_findings}</Badge>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}