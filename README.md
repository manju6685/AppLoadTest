# AppLoadTest - Performance Testing Platform

A comprehensive ASP.NET Core 9.0 web application for load testing, performance analysis, and diagnostics - ported from ASP.NET Web Forms.

## 🚀 Features

### Load Testing
- **Concurrent Request Testing**: Send 1-100 concurrent requests to any URL
- **Real-time Performance Metrics**: Track response times, success rates, and throughput
- **Statistical Analysis**: P50, P75, P90, P95, P99 percentiles
- **Response Time Distribution**: Visualize performance patterns
- **Status Code Tracking**: Monitor HTTP response codes (2xx, 3xx, 4xx, 5xx)
- **Connection Failure Detection**: Identify network and connectivity issues

### Security & Diagnostics
- **SSL/TLS Inspection**: 
  - Protocol version detection (TLS 1.2, 1.3, etc.)
  - Cipher algorithm and strength analysis
  - Hash algorithm inspection
  - Key exchange algorithm details
  
- **Certificate Information**:
  - Subject and issuer details
  - Validity period (from/to dates)
  - Certificate status (Valid/Expired)
  - Thumbprint and serial number
  - Signature algorithm

- **DNS Analysis**:
  - Hostname resolution
  - IP address listing (IPv4/IPv6)
  - Address count

- **TCP Connectivity**:
  - Connection latency measurement
  - Port reachability testing

### Azure Integration
- **Azure App Service Detection**: Automatically identifies Azure-hosted applications
- **Site Name Extraction**: Parses site information from Azure URLs
- **Extensible for Kusto Integration**: Ready for Azure monitoring data integration

### Visualizations
- **Response Time Chart**: Line chart showing request-by-request performance
- **Status Code Distribution**: Doughnut chart of HTTP status codes
- **Time Distribution**: Bar chart showing response time ranges
- **Error Categorization**: Clear breakdown of success/error types

## 🎯 Quick Start

### Prerequisites
- .NET 9.0 SDK or later
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Running the Application

1. **Build the project:**
   ```bash
   dotnet build
   ```

2. **Run the application:**
   ```bash
   dotnet run
   ```

3. **Access the application:**
   Open your browser to: `http://localhost:5044`

### Using VS Code Tasks
- Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
- Type "Tasks: Run Task"
- Select either:
  - "Build ASP.NET Core App" - Build only
  - "Run ASP.NET Core App" - Build and run

## 📖 Usage Guide

### Load Testing

1. **Enter Target URL**: Any valid HTTP/HTTPS endpoint
2. **Optional Authorization**: Add Bearer tokens or API keys if needed
3. **Set Request Count**: Choose between 1-100 concurrent requests
4. **Click "Run Load Test"**: Wait for results

#### Metrics Explained:
- **Success Rate**: Percentage of successful requests (2xx status codes)
- **Requests/Sec**: Throughput measurement
- **Avg Time**: Mean response time across all requests
- **Percentiles (P50-P99)**: Performance distribution analysis

### Site Diagnostics

1. **Enter Target URL**: The site you want to inspect
2. **Click "Fetch Site Diagnostics"**
3. **Review Three Sections**:
   - **Security Diagnostics**: SSL/TLS and certificate information
   - **General Information**: HTTP headers, protocol, hostname
   - **Azure App Service Info**: Azure-specific metadata (if applicable)

## 🛠️ Technology Stack

- **Framework**: ASP.NET Core 9.0
- **UI**: Razor Pages with custom CSS
- **Charts**: Chart.js 4.4.0
- **Architecture**: Model-View-Controller (MVC) pattern
- **HTTP Client**: HttpClientFactory for efficient connection pooling
- **Security**: TLS/SSL inspection via SslStream and X509Certificate2

## 📂 Project Structure

```
AppLoadTest/
├── Pages/
│   ├── Index.cshtml         # Main UI page
│   ├── Index.cshtml.cs      # Backend logic (647 lines)
│   ├── Error.cshtml         # Error page
│   ├── Privacy.cshtml       # Privacy page
│   └── Shared/
│       └── _Layout.cshtml   # Layout template
├── wwwroot/                 # Static files
├── Program.cs               # Application entry point
├── appsettings.json        # Configuration
└── README.md               # This file
```

## 🔬 Core Components

### IndexModel Class
- **ExecuteLoadTestAsync**: Orchestrates concurrent load testing
- **SendRequestWithDetailedTimingAsync**: Individual request handler with timing
- **CollectDiagnosticsAsync**: Gathers SSL/TLS, DNS, and TCP info
- **GetSslTlsInfoAsync**: Inspects SSL/TLS connection details
- **GetCertificateInfo**: Extracts X.509 certificate information
- **GetDnsInfo**: Resolves DNS entries
- **GetTcpPingInfo**: Tests TCP connectivity and latency
- **CalculateStatistics**: Computes percentiles and distributions

### Helper Classes
- **RequestResult**: Encapsulates individual request metrics
- **Statistics**: Statistical analysis results
- **DistributionBucket**: Time distribution grouping

## 🎨 Features Ported from ASP.NET Web Forms

This application is a complete port of the original ASP.NET Web Forms LoadTesting application with all functionality preserved:

✅ Load testing with configurable request counts  
✅ SSL/TLS protocol inspection  
✅ Certificate validation and information  
✅ DNS resolution and IP address detection  
✅ TCP connectivity testing  
✅ Azure App Service detection  
✅ Real-time chart visualizations  
✅ Statistical analysis (percentiles, distributions)  
✅ Error categorization by HTTP status code  
✅ Response time tracking  
✅ Authorization token support  

## 🔐 Security Considerations

- **Certificate Validation**: Currently accepts all certificates for testing purposes
  - In production, implement proper certificate validation
  - Use `ServerCertificateCustomValidationCallback` appropriately

- **HTTPS Redirection**: Configured in `Program.cs`
- **CORS**: Not enabled by default - add as needed for API scenarios
- **Rate Limiting**: Consider adding for production use

## 🚦 Performance Notes

- **Concurrent Requests**: Up to 100 simultaneous requests supported
- **Timeout**: 30-second timeout per request
- **Connection Pooling**: Automatic via HttpClientFactory
- **Cookie Management**: Enabled for session-based testing

## 🐛 Known Limitations

1. **Kusto Integration**: UI present but backend implementation requires Azure credentials
2. **ServicePointManager Warning**: Legacy API used for SSL protocol detection (SYSLIB0014)
3. **Certificate Validation**: Disabled for testing - enable for production

## 📊 Example Use Cases

1. **API Performance Testing**: Test REST API endpoints under load
2. **SSL Configuration Validation**: Verify TLS versions and cipher suites
3. **Certificate Expiration Monitoring**: Check certificate validity dates
4. **Azure App Service Health Checks**: Verify Azure deployment status
5. **Network Connectivity Testing**: Diagnose DNS and TCP issues

## 🔄 Migration from Web Forms

This project successfully migrates ASP.NET Web Forms functionality to modern ASP.NET Core:

- **From**: Server controls (`<asp:Button>`, `<asp:TextBox>`)
- **To**: HTML5 with JavaScript fetch API

- **From**: Postback model
- **To**: AJAX/REST API model with Razor Pages handlers

- **From**: ViewState
- **To**: Client-side state management

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear description

## 📧 Support

For issues, questions, or suggestions, please open an issue in the repository.

---

**Built with ❤️ using ASP.NET Core 9.0**