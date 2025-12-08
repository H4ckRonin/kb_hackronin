// Helper functions to extract metadata from file paths and content

export function extractMetadataFromPath(id: string) {
  // The ID from glob loader with base: "./certifications" should be relative to that base
  // Expected format: infrastructure/offensive-security/01-oscp/00-README.md
  
  // Remove 'certifications/' prefix if present
  let cleanId = id.startsWith('certifications/') 
    ? id.replace(/^certifications\//, '')
    : id;
  
  // Split into parts and filter out empty strings only
  const parts = cleanId.split('/').filter(p => p !== '');
  
  // Extract filename (last part, remove .md extension)
  const filename = parts.length > 0 ? parts[parts.length - 1].replace(/\.md$/, '') : '';
  
  // Extract metadata from path structure
  // Path format: category/vendor/certification/filename.md (4 parts)
  //          OR: category/vendor/filename.md (3 parts)
  // Example: infrastructure/offensive-security/01-oscp/00-README.md
  //          [0]            [1]                [2]        [3]
  let category = '';
  let vendor = '';
  let certification = '';
  
  // Handle 4-part paths: category/vendor/certification/filename.md
  if (parts.length >= 4) {
    category = parts[0] || '';
    vendor = parts[1] || '';
    certification = parts[2] || '';
    // filename is already extracted from parts[parts.length - 1]
  }
  // Handle 3-part paths: category/vendor/filename.md (no certification level)
  else if (parts.length === 3) {
    category = parts[0] || '';
    vendor = parts[1] || '';
    certification = ''; // No certification level for 3-part paths
    // filename is already extracted from parts[2]
  }
  // Handle 2-part paths: category/filename.md
  else if (parts.length === 2) {
    category = parts[0] || '';
    vendor = '';
    certification = '';
    // filename is already extracted from parts[1]
  }
  
  return { category, vendor, certification, filename };
}

export function generateTitleFromFilename(filename: string): string {
  return filename
    .replace(/\d+-/g, '') // Remove leading numbers
    .replace(/-/g, ' ') // Replace hyphens with spaces
    .replace(/\b\w/g, l => l.toUpperCase()); // Capitalize first letter of each word
}

// Format certification name - uppercase except for Pentest+ and Security+
export function formatCertificationName(certName: string): string {
  const normalized = certName.trim();
  const lowerNormalized = normalized.toLowerCase();
  
  // Check if it's Pentest+ or Security+ (case-insensitive)
  if (lowerNormalized === 'pentest+' || lowerNormalized === 'security+') {
    // Return with proper capitalization: Pentest+ or Security+
    return normalized.charAt(0).toUpperCase() + normalized.slice(1).toLowerCase();
  }
  
  // All other certifications should be uppercase
  return normalized.toUpperCase();
}

export function enrichCertData(cert: any) {
  const metadata = extractMetadataFromPath(cert.id);
  const title = cert.data.title || generateTitleFromFilename(metadata.filename);

  return {
    ...cert,
    data: {
      ...cert.data,
      title,
      // Always use extracted metadata (frontmatter can override)
      category: cert.data.category || metadata.category,
      vendor: cert.data.vendor || metadata.vendor,
      certification: cert.data.certification || metadata.certification,
    }
  };
}

export function enrichGuideData(guide: any) {
  const metadata = extractMetadataFromPath(guide.id);
  const title = guide.data.title || generateTitleFromFilename(metadata.filename);

  return {
    ...guide,
    data: {
      ...guide.data,
      title,
      // Always use extracted metadata (frontmatter can override)
      category: guide.data.category || metadata.category,
      vendor: guide.data.vendor || metadata.vendor,
      certification: guide.data.certification || metadata.certification,
    }
  };
}

// Extract phases from methodology content
export function extractPhases(content: string): Array<{ number: number; title: string; id: string }> {
  const phases: Array<{ number: number; title: string; id: string }> = [];
  
  // Match patterns like "## Phase 1: Title" or "### Phase 1: Title" or "## 1. Phase Title"
  const phasePatterns = [
    /^#{2,3}\s+Phase\s+(\d+):\s*(.+)$/gm,
    /^#{2,3}\s+(\d+)\.\s+(.+)$/gm,
    /^#{2,3}\s+Phase\s+(\d+)\s+(.+)$/gm,
  ];
  
  for (const pattern of phasePatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const number = parseInt(match[1], 10);
      const title = match[2].trim();
      const id = `phase-${number}`;
      
      // Avoid duplicates
      if (!phases.find(p => p.number === number)) {
        phases.push({ number, title, id });
      }
    }
  }
  
  return phases.sort((a, b) => a.number - b.number);
}

// Count phases in methodology content
export function countPhases(content: string): number {
  const phases = extractPhases(content);
  return phases.length;
}

// Extract tool mentions from content
export function extractTools(content: string): string[] {
  const tools: Set<string> = new Set();
  
  // Common tool patterns
  const toolPatterns = [
    // Tool names in code blocks or inline code
    /`([A-Za-z0-9-]+)`/g,
    // Tool names in lists or sections
    /-?\s*\*\*([A-Za-z0-9\s-]+)\*\*:/g,
    // Common tool names (case-insensitive)
    /\b(nmap|metasploit|burp|zap|sqlmap|hashcat|john|mimikatz|bloodhound|impacket|crackmapexec|responder|rubeus|powershell|python|bash|gobuster|dirb|feroxbuster|nikto|nuclei|linpeas|winpeas|sharphound|evil-winrm|psexec|smbclient|enum4linux|ldapsearch|theharvester|shodan|maltego|recon-ng|masscan|rustscan|nessus|openvas|postman|insomnia|wappalyzer|whatweb|wfuzz|ffuf|xsser|xss-hunter)\b/gi,
  ];
  
  for (const pattern of toolPatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const tool = match[1] || match[0];
      if (tool && tool.length > 2 && tool.length < 50) {
        tools.add(tool.toLowerCase().trim());
      }
    }
  }
  
  return Array.from(tools).sort();
}

// Extract techniques mentioned in content
export function extractTechniques(content: string): string[] {
  const techniques: Set<string> = new Set();
  
  // Common technique patterns
  const techniquePatterns = [
    // MITRE ATT&CK techniques
    /\b(T\d{4}\.\d{3})\b/g,
    // Common attack techniques
    /\b(sql injection|nosql injection|xss|cross-site scripting|csrf|command injection|ldap injection|xxe|path traversal|idor|privilege escalation|lateral movement|pass the hash|pass the ticket|kerberoasting|as-rep roasting|dcsync|golden ticket|silver ticket|llmnr poisoning|ntlm relay|credential dumping|persistence|defense evasion|collection|exfiltration|impact)\b/gi,
  ];
  
  for (const pattern of techniquePatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const technique = match[1] || match[0];
      if (technique) {
        techniques.add(technique.toLowerCase().trim());
      }
    }
  }
  
  return Array.from(techniques).sort();
}

// Enrich methodology data with extracted metadata
export function enrichMethodologyData(methodology: any) {
  const parts = methodology.id.split('/').filter((p: string) => p);
  const categoryFromPath = parts.length > 0 ? parts[0] : '';
  const category = methodology.data.category || categoryFromPath || 'general';
  const title = methodology.data.title || generateTitleFromFilename(parts[parts.length - 1]?.replace('.md', '') || methodology.id);
  
  // Extract metadata from body if available
  const body = methodology.body || '';
  const extractedPhases = extractPhases(body);
  const phaseCount = methodology.data.phases || extractedPhases.length || countPhases(body);
  const extractedTools = extractTools(body);
  const extractedTechniques = extractTechniques(body);
  
  return {
    ...methodology,
    data: {
      ...methodology.data,
      title,
      category: category.toLowerCase().replace(/\s+/g, '-'),
      phases: phaseCount,
      // Store extracted data for use in components
      _extractedPhases: extractedPhases,
      _extractedTools: extractedTools,
      _extractedTechniques: extractedTechniques,
    }
  };
}