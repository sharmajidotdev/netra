flowchart TD
    A[Start: main.go] --> B[cli.Execute]
    B --> C[cobra rootCmd.Execute]
    C --> D{Command Type?}
    
    D -->|Default Scan| E[runScan]
    D -->|Config| F[configCmd]
    
    E --> G[Initialize Scanner]
    G --> H[Configure Scanner Options]
    
    H --> I{Scan Mode?}
    
    I -->|Regular Files| J[Regular File Scan]
    I -->|Diff File| K[Scan Diff File]
    I -->|Git Commit Range| L[Scan Commit Range]
    I -->|Staged Changes| M[Scan Staged Changes]
    
    J --> N[Process Files]
    K --> N
    L --> N
    M --> N
    
    N --> O[Scanner Worker Pool]
    O --> P[Apply Detection Rules]
    
    P -->|Optional| Q[LLM Analysis]
    P --> R[Generate Findings]
    
    R --> S{Output Format}
    S -->|JSON| T[JSON Output]
    S -->|Human| U[Human Readable Output]
    S -->|SARIF| V[SARIF Output]
    
    T --> W[Exit]
    U --> W
    V --> W
    
    subgraph "Scanner Components"
    O
    P
    Q
    end
    
    subgraph "Output Handlers"
    T
    U
    V
    end