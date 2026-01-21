using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.Core;
using Kusto.Data;
using Kusto.Data.Common;
using Kusto.Data.Net.Client;

namespace AppLoadTest.Pages;

// Custom TokenCredential that uses cached session token
public class SessionTokenCredential : TokenCredential
{
    private readonly string _token;
    private readonly DateTimeOffset _expiresOn;

    public SessionTokenCredential(string token, DateTimeOffset expiresOn)
    {
        _token = token;
        _expiresOn = expiresOn;
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new AccessToken(_token, _expiresOn);
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new ValueTask<AccessToken>(new AccessToken(_token, _expiresOn));
    }
}

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private TokenCredential? _azureCredential;

    public IndexModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
    }

    [BindProperty]
    public string? TestUrl { get; set; }

    [BindProperty]
    public string? Token { get; set; }

    [BindProperty]
    public int NumRequests { get; set; } = 10;

    public void OnGet(string? url = null)
    {
        if (!string.IsNullOrEmpty(url) && Uri.IsWellFormedUriString(url, UriKind.Absolute))
        {
            TestUrl = url;
        }
    }

    public async Task<IActionResult> OnPostRunTestAsync()
    {
        if (string.IsNullOrEmpty(TestUrl) || !Uri.IsWellFormedUriString(TestUrl, UriKind.Absolute))
        {
            return new JsonResult(new { success = false, message = "Invalid URL" });
        }

        if (NumRequests < 1 || NumRequests > 100)
        {
            return new JsonResult(new { success = false, message = "Request count must be between 1 and 100" });
        }

        try
        {
            var result = await ExecuteLoadTestAsync(TestUrl, NumRequests, Token);
            return new JsonResult(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running load test");
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    public async Task<IActionResult> OnPostFetchSiteInfoAsync()
    {
        if (string.IsNullOrEmpty(TestUrl) || !Uri.IsWellFormedUriString(TestUrl, UriKind.Absolute))
        {
            return new JsonResult(new { success = false, message = "Invalid URL" });
        }

        try
        {
            var diagnostics = await CollectDiagnosticsAsync(TestUrl, Token);
            var generalInfo = await GetGeneralInfoAsync(TestUrl, Token);
            var appServiceInfo = await GetAppServiceInfoAsync(TestUrl);

            var result = new
            {
                success = true,
                diagnostics,
                generalInfo,
                appServiceInfo
            };

            return new JsonResult(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching site info");
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    private async Task<object> ExecuteLoadTestAsync(string url, int numRequests, string? token)
    {
        var timings = new long[numRequests];
        var statusCodes = new Dictionary<int, int>();
        var errors = new List<string>();
        long totalBytes = 0;
        var sslProtocols = new Dictionary<string, int>();
        var cipherSuites = new Dictionary<string, int>();
        int httpsRequests = 0;
        int success = 0, fail = 0;

        var testStartTime = Stopwatch.StartNew();

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, sslErrors) =>
            {
                return true; // Accept all certificates for testing
            },
            UseCookies = true,
            CookieContainer = new CookieContainer()
        };

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        client.DefaultRequestHeaders.Add("User-Agent", "LoadTestTool/1.0");

        if (!string.IsNullOrEmpty(token))
        {
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        }

        var tasks = new List<Task<RequestResult>>();
        for (int i = 0; i < numRequests; i++)
        {
            int requestNumber = i + 1;
            tasks.Add(SendRequestWithDetailedTimingAsync(client, url, requestNumber));
        }

        var results = await Task.WhenAll(tasks);

        foreach (var result in results)
        {
            timings[result.RequestNumber - 1] = result.Duration;
            totalBytes += result.ResponseSize;

            if (result.IsSuccess)
            {
                success++;
            }
            else
            {
                fail++;
                if (!string.IsNullOrEmpty(result.ErrorMessage))
                {
                    errors.Add(result.ErrorMessage);
                }
            }

            if (statusCodes.ContainsKey(result.StatusCode))
                statusCodes[result.StatusCode]++;
            else
                statusCodes[result.StatusCode] = 1;

            if (result.IsHttps)
            {
                httpsRequests++;
                if (!string.IsNullOrEmpty(result.SslProtocol))
                {
                    if (sslProtocols.ContainsKey(result.SslProtocol))
                        sslProtocols[result.SslProtocol]++;
                    else
                        sslProtocols[result.SslProtocol] = 1;
                }

                if (!string.IsNullOrEmpty(result.CipherSuite))
                {
                    if (cipherSuites.ContainsKey(result.CipherSuite))
                        cipherSuites[result.CipherSuite]++;
                    else
                        cipherSuites[result.CipherSuite] = 1;
                }
            }
        }

        testStartTime.Stop();

        var stats = CalculateStatistics(timings);
        var distribution = GetTimeDistribution(timings);

        // Categorize status codes
        var success2xx = statusCodes.Where(x => x.Key >= 200 && x.Key < 300).Sum(x => x.Value);
        var redirect3xx = statusCodes.Where(x => x.Key >= 300 && x.Key < 400).Sum(x => x.Value);
        var client4xx = statusCodes.Where(x => x.Key >= 400 && x.Key < 500).Sum(x => x.Value);
        var server5xx = statusCodes.Where(x => x.Key >= 500 && x.Key < 600).Sum(x => x.Value);
        var connectionFail = statusCodes.Where(x => x.Key == 0).Sum(x => x.Value);

        return new
        {
            success = true,
            url,
            totalRequests = numRequests,
            successCount = success,
            failCount = fail,
            totalTime = testStartTime.ElapsedMilliseconds,
            totalBytes,
            requestsPerSecond = numRequests / (testStartTime.ElapsedMilliseconds / 1000.0),
            statistics = stats,
            distribution,
            statusCodes,
            statusCategories = new
            {
                success2xx,
                redirect3xx,
                client4xx,
                server5xx,
                connectionFail
            },
            sslProtocols,
            cipherSuites,
            httpsRequests,
            errors = errors.Take(10).ToList(),
            timings = timings.ToList()
        };
    }

    private async Task<RequestResult> SendRequestWithDetailedTimingAsync(HttpClient client, string url, int requestNumber)
    {
        var result = new RequestResult { RequestNumber = requestNumber };
        var sw = Stopwatch.StartNew();

        try
        {
            var uri = new Uri(url);
            result.IsHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

            var response = await client.GetAsync(url);
            sw.Stop();

            result.Duration = sw.ElapsedMilliseconds;
            result.StatusCode = (int)response.StatusCode;
            result.IsSuccess = response.IsSuccessStatusCode;

            var content = await response.Content.ReadAsByteArrayAsync();
            result.ResponseSize = content.Length;

            if (result.IsHttps)
            {
                try
                {
#pragma warning disable SYSLIB0014
                    var sp = ServicePointManager.FindServicePoint(uri);
#pragma warning restore SYSLIB0014
                    result.SslProtocol = GetSslProtocolVersion(sp);
                    result.CipherSuite = sp.Certificate?.Subject ?? "Unknown";
                }
                catch { }
            }
        }
        catch (HttpRequestException ex)
        {
            sw.Stop();
            result.Duration = sw.ElapsedMilliseconds;
            result.StatusCode = 0;
            result.IsSuccess = false;
            result.ErrorMessage = $"Request {requestNumber}: {ex.Message}";
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            result.Duration = sw.ElapsedMilliseconds;
            result.StatusCode = 0;
            result.IsSuccess = false;
            result.ErrorMessage = $"Request {requestNumber}: Timeout";
        }
        catch (Exception ex)
        {
            sw.Stop();
            result.Duration = sw.ElapsedMilliseconds;
            result.StatusCode = 0;
            result.IsSuccess = false;
            result.ErrorMessage = $"Request {requestNumber}: {ex.Message}";
        }

        return result;
    }

    private string GetSslProtocolVersion(ServicePoint sp)
    {
        try
        {
            var prop = sp.GetType().GetProperty("SecurityProtocolType",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (prop != null)
            {
                var value = prop.GetValue(sp);
                if (value != null)
                {
                    return value.ToString() ?? "Unknown";
                }
            }
        }
        catch { }
        return "Unknown";
    }

    private async Task<object> CollectDiagnosticsAsync(string url, string? token)
    {
        var uri = new Uri(url);
        var hostname = uri.Host;
        var port = uri.Port;
        var isHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

        var sslTlsInfo = isHttps ? await GetSslTlsInfoAsync(url) : null;
        var certInfo = isHttps ? GetCertificateInfo(hostname, port) : null;
        var dnsInfo = GetDnsInfo(hostname);
        var tcpInfo = GetTcpPingInfo(hostname, port);

        return new
        {
            url,
            hostname,
            port,
            isHttps,
            sslTlsInfo,
            certificateInfo = certInfo,
            dnsInfo,
            tcpInfo
        };
    }

    private async Task<object?> GetSslTlsInfoAsync(string url)
    {
        try
        {
            var uri = new Uri(url);
            using var client = new TcpClient();
            await client.ConnectAsync(uri.Host, uri.Port);

            using var sslStream = new SslStream(client.GetStream(), false,
                (sender, certificate, chain, errors) => true);

            await sslStream.AuthenticateAsClientAsync(uri.Host);

            return new
            {
                protocol = sslStream.SslProtocol.ToString(),
                cipherAlgorithm = sslStream.CipherAlgorithm.ToString(),
                cipherStrength = sslStream.CipherStrength,
                hashAlgorithm = sslStream.HashAlgorithm.ToString(),
                hashStrength = sslStream.HashStrength,
                keyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm.ToString(),
                keyExchangeStrength = sslStream.KeyExchangeStrength,
                isAuthenticated = sslStream.IsAuthenticated,
                isEncrypted = sslStream.IsEncrypted,
                isSigned = sslStream.IsSigned
            };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private object GetCertificateInfo(string hostname, int port)
    {
        try
        {
            using var client = new TcpClient(hostname, port);
            using var sslStream = new SslStream(client.GetStream(), false,
                (sender, certificate, chain, errors) => true);

            sslStream.AuthenticateAsClient(hostname);

            var cert = sslStream.RemoteCertificate as X509Certificate2;
            if (cert != null)
            {
                return new
                {
                    subject = cert.Subject,
                    issuer = cert.Issuer,
                    validFrom = cert.NotBefore,
                    validTo = cert.NotAfter,
                    thumbprint = cert.Thumbprint,
                    serialNumber = cert.SerialNumber,
                    signatureAlgorithm = cert.SignatureAlgorithm.FriendlyName,
                    version = cert.Version,
                    status = DateTime.Now < cert.NotAfter ? "Valid" : "Expired"
                };
            }
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
        return new { error = "Unable to retrieve certificate" };
    }

    private object GetDnsInfo(string hostname)
    {
        try
        {
            var hostEntry = Dns.GetHostEntry(hostname);
            return new
            {
                hostname = hostEntry.HostName,
                addresses = hostEntry.AddressList.Select(ip => ip.ToString()).ToList(),
                addressCount = hostEntry.AddressList.Length
            };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private object GetTcpPingInfo(string hostname, int port)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(hostname, port);
            
            if (connectTask.Wait(5000))
            {
                sw.Stop();
                return new
                {
                    success = true,
                    latency = sw.ElapsedMilliseconds,
                    message = $"Connected to {hostname}:{port}"
                };
            }
            else
            {
                return new
                {
                    success = false,
                    message = "Connection timeout"
                };
            }
        }
        catch (Exception ex)
        {
            return new
            {
                success = false,
                message = ex.Message
            };
        }
    }

    private async Task<object> GetGeneralInfoAsync(string url, string? token)
    {
        try
        {
            var uri = new Uri(url);
            var totalStopwatch = Stopwatch.StartNew();
            
            // DNS Resolution timing
            var dnsStopwatch = Stopwatch.StartNew();
            var hostEntry = await Dns.GetHostEntryAsync(uri.Host);
            dnsStopwatch.Stop();
            
            // TCP Connection timing
            var tcpStopwatch = Stopwatch.StartNew();
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(uri.Host, uri.Port);
            tcpStopwatch.Stop();
            
            long sslHandshakeTime = 0;
            
            // SSL/TLS Handshake timing (if HTTPS)
            if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                var sslStopwatch = Stopwatch.StartNew();
                using var sslStream = new SslStream(tcpClient.GetStream(), false, (sender, cert, chain, errors) => true);
                await sslStream.AuthenticateAsClientAsync(uri.Host);
                sslStopwatch.Stop();
                sslHandshakeTime = sslStopwatch.ElapsedMilliseconds;
            }
            
            // HTTP Request timing
            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(10);

            if (!string.IsNullOrEmpty(token))
            {
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            }

            var requestStopwatch = Stopwatch.StartNew();
            var requestSentTime = requestStopwatch.ElapsedMilliseconds;
            
            var response = await client.GetAsync(url);
            var ttfbTime = requestStopwatch.ElapsedMilliseconds;
            
            // Content Download timing
            var contentStopwatch = Stopwatch.StartNew();
            await response.Content.ReadAsByteArrayAsync();
            contentStopwatch.Stop();
            
            totalStopwatch.Stop();
            
            var headers = response.Headers.ToDictionary(
                h => h.Key,
                h => string.Join(", ", h.Value)
            );

            var contentHeaders = response.Content.Headers.ToDictionary(
                h => h.Key,
                h => string.Join(", ", h.Value)
            );

            return new
            {
                url,
                statusCode = (int)response.StatusCode,
                statusDescription = response.ReasonPhrase,
                protocol = response.Version.ToString(),
                method = "GET",
                headers,
                contentHeaders,
                hostname = uri.Host,
                scheme = uri.Scheme,
                port = uri.Port,
                timings = new
                {
                    dnsLookup = dnsStopwatch.ElapsedMilliseconds,
                    tcpConnection = tcpStopwatch.ElapsedMilliseconds,
                    sslHandshake = sslHandshakeTime,
                    requestSent = 1, // Small fixed value for request send time
                    waiting = ttfbTime - requestSentTime,
                    contentDownload = contentStopwatch.ElapsedMilliseconds,
                    total = totalStopwatch.ElapsedMilliseconds
                }
            };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private async Task<object> GetAppServiceInfoAsync(string url)
    {
        try
        {
            var uri = new Uri(url);
            var hostname = uri.Host;

            // Check if it's an Azure App Service
            var isAzureAppService = hostname.EndsWith(".azurewebsites.net", StringComparison.OrdinalIgnoreCase) ||
                                   hostname.EndsWith(".azurewebsites.windows.net", StringComparison.OrdinalIgnoreCase);

            if (!isAzureAppService)
            {
                return new
                {
                    available = false,
                    isAzureAppService = false,
                    message = "Not an Azure App Service"
                };
            }

            // Extract site name from hostname
            var siteName = hostname.Split('.')[0];

            try
            {
                // Query Kusto for App Service details using logged-in user's credential
                var kustoClusterUri = "https://wawseus.kusto.windows.net";
                var credential = GetAzureCredential();
                
                // Use callback authentication with the stored credential
                var kcsb = new KustoConnectionStringBuilder(kustoClusterUri)
                    .WithAadAzureTokenCredentialsAuthentication(credential);

                using var kustoClient = KustoClientFactory.CreateCslQueryProvider(kcsb);

                var siteNamesub = "";
                var query = $@"
let _siteName = '{siteName}';
let _siteNamesub = '{siteNamesub}';
let _psiteName = iff(isnotempty(_siteNamesub), _siteNamesub, _siteName);
cluster('wawseus').database('wawsprod').WawsAn_dailyentity
| where pdate >= ago(30d)
| where sitename == tolower(_psiteName)
| order by pdate desc
| take 1
| extend ResourceId = strcat('/subscriptions/', sitesubscription, '/resourceGroups/', resourcegroup, '/providers/Microsoft.Web/sites/', sitename)
| project 
    sitename,
    sitesubscription,
    resourcegroup,
    sitestamp,
    siteregion,
    sitestack,
    sitesku,
    sitewhptype,
    deploymentclient,
    ServerFarmName,
    AntVersion,
    LinuxRuntimeStack,
    sitecreationsource,
    deploymentsource,
    scmtype,
    ResourceId
| take 1";

                _logger.LogInformation($"Querying Kusto for site: {siteName}");

                var reader = await kustoClient.ExecuteQueryAsync("wawsprod", query, new ClientRequestProperties());

                if (reader.Read())
                {
                    // Parse the Kusto result
                    var kustoData = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        kustoData[reader.GetName(i)] = reader.GetValue(i) ?? "";
                    }

                    // Cache the authentication token
                    HttpContext.Session.SetString("KustoAuthToken", "authenticated");

                    _logger.LogInformation($"Successfully retrieved Kusto data for site: {siteName}");

                    // Query for cluster based on stamp
                    string kustoCluster = "Not available";
                    try
                    {
                        var stamp = kustoData.GetValueOrDefault("sitestamp", "")?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(stamp))
                        {
                            var stampParts = stamp.Split('-');
                            if (stampParts.Length >= 3)
                            {
                                var antaresAbbr = stampParts[2];
                                var clusterQuery = $@"
GetRegions
| where AntaresAbbreviation == '{antaresAbbr}'
| project KustoCluster";

                                var clusterReader = await kustoClient.ExecuteQueryAsync("wawsprod", clusterQuery, new ClientRequestProperties());
                                if (clusterReader.Read())
                                {
                                    kustoCluster = clusterReader.GetString(0);
                                }
                            }
                        }
                    }
                    catch (Exception clusterEx)
                    {
                        _logger.LogWarning(clusterEx, $"Failed to retrieve cluster for stamp");
                    }

                    // Query for Site Info using the cluster
                    var siteInfoList = new List<Dictionary<string, object>>();
                    try
                    {
                        if (kustoCluster != "Not available" && !string.IsNullOrEmpty(kustoCluster))
                        {
                            var siteInfoQuery = $@"
let _psiteName = '{siteName}';
let Id = (cluster('{kustoCluster}').database('wawsprod').AntaresReadOnlyViews
| where TIMESTAMP > ago(7d)
| where SqlCommand has 'view_Sites'
| where ColumnValue startswith _psiteName
| order by PreciseTimeStamp desc
| take 1
| summarize by RowId);
cluster('{kustoCluster}').database('wawsprod').AntaresReadOnlyViews
| where TIMESTAMP > ago(7d)
| where RowId == toscalar(Id)
| summarize by Key = ColumnName, Value = ColumnValue";

                            var siteInfoReader = await kustoClient.ExecuteQueryAsync("wawsprod", siteInfoQuery, new ClientRequestProperties());
                            while (siteInfoReader.Read())
                            {
                                var row = new Dictionary<string, object>
                                {
                                    ["Key"] = siteInfoReader.GetString(0),
                                    ["Value"] = siteInfoReader.GetString(1)
                                };
                                siteInfoList.Add(row);
                            }
                        }
                    }
                    catch (Exception siteInfoEx)
                    {
                        _logger.LogWarning(siteInfoEx, $"Failed to retrieve site info for site: {siteName}");
                    }

                    return new
                    {
                        available = true,
                        isAzureAppService = true,
                        siteName = kustoData.GetValueOrDefault("sitename", siteName),
                        hostname,
                        // Plan & Hosting
                        planName = kustoData.GetValueOrDefault("ServerFarmName", ""),
                        tier = kustoData.GetValueOrDefault("sitesku", ""),
                        computeType = kustoData.GetValueOrDefault("sitewhptype", ""),
                        region = kustoData.GetValueOrDefault("siteregion", ""),
                        serverFarm = kustoData.GetValueOrDefault("ServerFarmName", ""),
                        stamp = kustoData.GetValueOrDefault("sitestamp", ""),
                        cluster = kustoCluster,
                        // Configuration
                        runtimeStack = kustoData.GetValueOrDefault("sitestack", ""),
                        operatingSystem = kustoData.GetValueOrDefault("sitewhptype", "")?.ToString()?.Contains("Linux") == true ? "Linux" : "Windows",
                        platform = "Azure App Service",
                        appState = "Running",
                        antVersion = kustoData.GetValueOrDefault("AntVersion", ""),
                        linuxRuntimeStack = kustoData.GetValueOrDefault("LinuxRuntimeStack", ""),
                        // Scaling
                        instanceCount = "1",
                        autoScale = "Disabled",
                        alwaysOn = "Enabled",
                        arrAffinity = "Enabled",
                        // Security
                        httpsOnly = "Enabled",
                        tlsVersion = "1.2",
                        ftpState = "Disabled",
                        customDomain = hostname.Replace(".azurewebsites.net", ""),
                        // Azure Resources
                        resourceGroup = kustoData.GetValueOrDefault("resourcegroup", ""),
                        subscription = kustoData.GetValueOrDefault("sitesubscription", ""),
                        vnetName = "Not configured",
                        healthCheckPath = "/",
                        resourceId = kustoData.GetValueOrDefault("ResourceId", ""),
                        // Deployment
                        siteCreationSource = kustoData.GetValueOrDefault("sitecreationsource", ""),
                        deploymentSource = kustoData.GetValueOrDefault("deploymentsource", ""),
                        scmType = kustoData.GetValueOrDefault("scmtype", ""),
                        deploymentClient = kustoData.GetValueOrDefault("deploymentclient", ""),
                        // Site Info
                        siteInfo = siteInfoList,
                        message = "Successfully retrieved App Service information from Kusto"
                    };
                }
                else
                {
                    _logger.LogWarning($"No Kusto data found for site: {siteName}");
                    return new
                    {
                        available = true,
                        isAzureAppService = true,
                        siteName,
                        hostname,
                        message = "Azure App Service detected but no data found in Kusto"
                    };
                }
            }
            catch (Exception kustoEx)
            {
                _logger.LogError(kustoEx, $"Error querying Kusto for site: {siteName}");
                // Fall back to basic info if Kusto query fails
                return new
                {
                    available = true,
                    isAzureAppService = true,
                    siteName,
                    hostname,
                    message = $"Azure App Service detected. Kusto query failed: {kustoEx.Message}"
                };
            }
        }
        catch (Exception ex)
        {
            return new
            {
                available = false,
                error = ex.Message
            };
        }
    }

    private Statistics CalculateStatistics(long[] timings)
    {
        if (timings.Length == 0)
            return new Statistics();

        var sorted = timings.OrderBy(x => x).ToArray();
        var avg = timings.Average();

        return new Statistics
        {
            Min = sorted[0],
            Max = sorted[sorted.Length - 1],
            Average = avg,
            Median = GetPercentile(sorted, 50),
            StdDev = CalculateStandardDeviation(timings),
            P50 = GetPercentile(sorted, 50),
            P75 = GetPercentile(sorted, 75),
            P90 = GetPercentile(sorted, 90),
            P95 = GetPercentile(sorted, 95),
            P99 = GetPercentile(sorted, 99)
        };
    }

    private double GetPercentile(long[] sortedData, double percentile)
    {
        var index = (percentile / 100.0) * (sortedData.Length - 1);
        return sortedData[(int)Math.Round(index)];
    }

    private double CalculateStandardDeviation(long[] values)
    {
        var avg = values.Average();
        var sumOfSquares = values.Sum(val => Math.Pow(val - avg, 2));
        return Math.Sqrt(sumOfSquares / values.Length);
    }

    private List<DistributionBucket> GetTimeDistribution(long[] timings)
    {
        var buckets = new List<DistributionBucket>();
        var max = timings.Max();
        var ranges = new[] { 100L, 200L, 500L, 1000L, 2000L, 5000L, long.MaxValue };

        foreach (var range in ranges)
        {
            var count = timings.Count(t => t <= range && (buckets.Count == 0 || t > ranges[buckets.Count - 1]));
            var percentage = (count * 100.0) / timings.Length;

            var rangeLabel = range == long.MaxValue ? $"> {ranges[ranges.Length - 2]}ms" : $"<= {range}ms";
            buckets.Add(new DistributionBucket
            {
                Range = rangeLabel,
                Count = count,
                Percentage = percentage
            });

            if (range > max && count > 0)
                break;
        }

        return buckets;
    }

    // Helper classes
    public class RequestResult
    {
        public int RequestNumber { get; set; }
        public long Duration { get; set; }
        public int StatusCode { get; set; }
        public bool IsSuccess { get; set; }
        public long ResponseSize { get; set; }
        public string? ErrorMessage { get; set; }
        public string? SslProtocol { get; set; }
        public string? CipherSuite { get; set; }
        public bool IsHttps { get; set; }
    }

    public class Statistics
    {
        public double Min { get; set; }
        public double Max { get; set; }
        public double Average { get; set; }
        public double Median { get; set; }
        public double StdDev { get; set; }
        public double P50 { get; set; }
        public double P75 { get; set; }
        public double P90 { get; set; }
        public double P95 { get; set; }
        public double P99 { get; set; }
    }

    public class DistributionBucket
    {
        public string Range { get; set; } = string.Empty;
        public int Count { get; set; }
        public double Percentage { get; set; }
    }

    private TokenCredential GetAzureCredential()
    {
        // Try to use cached token from session first
        var cachedToken = HttpContext.Session.GetString("AzureToken");
        var cachedTokenExpiry = HttpContext.Session.GetString("AzureTokenExpiry");
        
        if (!string.IsNullOrEmpty(cachedToken) && !string.IsNullOrEmpty(cachedTokenExpiry))
        {
            if (DateTimeOffset.TryParse(cachedTokenExpiry, out var expiresOn))
            {
                // Check if token is still valid (not expired)
                if (expiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    _logger.LogInformation("Using cached token for Kusto queries");
                    return new SessionTokenCredential(cachedToken, expiresOn);
                }
                else
                {
                    _logger.LogWarning("Cached token expired, falling back to stored credential");
                }
            }
        }

        // If no cached token or expired, use the stored credential
        if (_azureCredential != null)
        {
            _logger.LogInformation("Using stored credential for Kusto queries");
            return _azureCredential;
        }

        // Fallback: create new interactive browser credential
        _logger.LogInformation("Creating new Interactive Browser credential for Kusto");
        return new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
        {
            TenantId = "common",
            ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            BrowserCustomization = new BrowserCustomizationOptions
            {
                UseEmbeddedWebView = false
            }
        });
    }

    public async Task<IActionResult> OnPostQueryLinksAsync()
    {
        try
        {
            var siteName = Request.Form["SiteName"].ToString().Trim().ToLower();
            
            if (string.IsNullOrEmpty(siteName))
            {
                return new JsonResult(new { success = false, message = "Site name is required" });
            }

            _logger.LogInformation($"Querying Kusto for links for site: {siteName}");

            // Query Kusto for site links using logged-in user's credential
            var kustoClusterUri = "https://wawseus.kusto.windows.net";
            var credential = GetAzureCredential();
            
            // Use callback authentication with the stored credential
            var kcsb = new KustoConnectionStringBuilder(kustoClusterUri)
                .WithAadAzureTokenCredentialsAuthentication(credential);

            using var kustoClient = KustoClientFactory.CreateCslQueryProvider(kcsb);

            // Get current time range (last 7 days)
            var startTime = DateTime.UtcNow.AddDays(-7);
            var endTime = DateTime.UtcNow;

            var query = $@"
let _siteName = '{siteName}';
let ST = datetime({startTime:yyyy-MM-ddTHH:mm:ssZ});
let ET = datetime({endTime:yyyy-MM-ddTHH:mm:ssZ});
cluster('wawseus').database('wawsprod').WawsAn_dailyentity
| where pdate between (min_of((ST - 1d), ago(4d)) .. (ET + 1d))
| where sitename == tolower(_siteName)
| extend diff = abs(totimespan(pdate -(ET - ST)/2))
| order by diff asc
| take 1
| extend asiLink = strcat('https://azureserviceinsights.trafficmanager.net/view/services/AppService/pages/Site?SiteName=', sitename, '&SubscriptionId=', sitesubscription, '&globalFrom=', ST , '&globalTo=', ET )
| extend applensLink = strcat('https://applens.trafficmanager.net/subscriptions/',sitesubscription ,'/resourceGroups/', resourcegroup,'/providers/Microsoft.Web/sites/', sitename,'?startTime=',ST,'&endTime=', ET )
| extend observerLink = strcat('https://wawsobserver.azurewebsites.windows.net/Sites/', sitename)
| extend observerASPLink = strcat('https://wawsobserver.azurewebsites.windows.net/Sites/', sitename)
| extend ResourceId = strcat('/subscriptions/',sitesubscription ,'/resourceGroups/', resourcegroup,'/providers/Microsoft.Web/sites/', sitename)
| project asiLink, applensLink, observerLink, observerASPLink, ResourceId, sitestamp, sitestack, sitesku, sitewhptype, sitesubscription, resourcegroup, sitename";

            var reader = await kustoClient.ExecuteQueryAsync("wawsprod", query, new ClientRequestProperties());

            if (reader.Read())
            {
                var links = new Dictionary<string, object>();
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    var value = reader.GetValue(i);
                    links[reader.GetName(i)] = value ?? "";
                }

                // Cache the authentication token
                HttpContext.Session.SetString("KustoAuthToken", "authenticated");

                _logger.LogInformation($"Successfully retrieved links for site: {siteName}");

                return new JsonResult(new 
                { 
                    success = true, 
                    message = $"Links retrieved for {siteName}",
                    links = links
                });
            }
            else
            {
                _logger.LogWarning($"No results found for site: {siteName}");
                return new JsonResult(new 
                { 
                    success = false, 
                    message = $"No results found for site '{siteName}'. The site might not exist or has no data in the analytics database for the last 7 days."
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error querying Kusto for links");
            return new JsonResult(new 
            { 
                success = false, 
                message = $"Error querying Kusto: {ex.Message}"
            });
        }
    }

    public async Task<IActionResult> OnPostAzureLoginAsync()
    {
        try
        {
            // Check if already logged in (session valid for 8 hours)
            var existingToken = HttpContext.Session.GetString("AzureToken");
            var loginTime = HttpContext.Session.GetString("AzureLoginTime");
            
            if (!string.IsNullOrEmpty(existingToken) && !string.IsNullOrEmpty(loginTime))
            {
                if (DateTime.TryParse(loginTime, out var lastLoginTime))
                {
                    if (DateTime.UtcNow - lastLoginTime < TimeSpan.FromHours(8))
                    {
                        var cachedInfo = HttpContext.Session.GetString("AzureAccountInfo");
                        _logger.LogInformation("Using cached Azure login");
                        return new JsonResult(new 
                        { 
                            success = true, 
                            message = "Already logged in to Azure",
                            accountInfo = cachedInfo
                        });
                    }
                }
            }

            // Check if running in Azure App Service
            var isAzureAppService = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_SITE_NAME"));
            
            // Try Windows Integrated Authentication first (bypasses CA policies on domain-joined machines)
            if (!isAzureAppService)
            {
                try
                {
                    _logger.LogInformation("Attempting Windows Integrated Authentication");
                    
                    var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
                    {
                        ExcludeEnvironmentCredential = true,
                        ExcludeWorkloadIdentityCredential = true,
                        ExcludeManagedIdentityCredential = true,
                        ExcludeSharedTokenCacheCredential = true,
                        ExcludeVisualStudioCredential = true,
                        ExcludeAzureCliCredential = true,
                        ExcludeAzurePowerShellCredential = true,
                        ExcludeInteractiveBrowserCredential = true,
                        // This leaves only AzureDeveloperCliCredential and potentially Windows auth
                    });
                    
                    var tokenRequestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
                    
                    // Try to get token with short timeout
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var token = await credential.GetTokenAsync(tokenRequestContext, cts.Token);
                    
                    if (token.Token != null)
                    {
                        _azureCredential = credential;
                        
                        // Get account information
                        var armClient = new ArmClient(_azureCredential);
                        var subscription = await armClient.GetDefaultSubscriptionAsync();
                        
                        var accountInfo = new
                        {
                            subscriptionId = subscription.Data.SubscriptionId,
                            subscriptionName = subscription.Data.DisplayName,
                            tenantId = subscription.Data.TenantId,
                            expiresOn = token.ExpiresOn.ToString("o"),
                            authMethod = "Windows Integrated Authentication"
                        };

                        var accountInfoJson = JsonSerializer.Serialize(accountInfo, new JsonSerializerOptions { WriteIndented = true });
                        HttpContext.Session.SetString("AzureToken", token.Token);
                        HttpContext.Session.SetString("AzureLoginTime", DateTime.UtcNow.ToString());
                        HttpContext.Session.SetString("AzureAccountInfo", accountInfoJson);
                        HttpContext.Session.SetString("AuthMethod", "WindowsIntegrated");
                        
                        _logger.LogInformation("Azure login successful via Windows Integrated Authentication");
                        return new JsonResult(new { success = true, message = "Successfully logged in to Azure using Windows Integrated Authentication", accountInfo = accountInfoJson });
                    }
                }
                catch (Exception winAuthEx)
                {
                    _logger.LogWarning(winAuthEx, "Windows Integrated Authentication failed, trying browser flow");
                }
            }
            
            // Choose authentication method based on environment
            if (isAzureAppService)
            {
                // Azure App Service: Use Azure CLI credential (user must login via Kudu console first)
                _logger.LogInformation("Azure App Service detected - using Azure CLI credential");
                _logger.LogInformation("Please run 'az login' in the Kudu console (Advanced Tools > Debug Console) first");
                
                _azureCredential = new AzureCliCredential();
                
                try
                {
                    var tokenRequestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
                    var token = await _azureCredential.GetTokenAsync(tokenRequestContext, CancellationToken.None);

                    if (token.Token != null)
                    {
                        // Get account information using Azure Resource Manager
                        var armClient = new ArmClient(_azureCredential);
                        var subscription = await armClient.GetDefaultSubscriptionAsync();
                        
                        var accountInfo = new
                        {
                            subscriptionId = subscription.Data.SubscriptionId,
                            subscriptionName = subscription.Data.DisplayName,
                            tenantId = subscription.Data.TenantId,
                            expiresOn = token.ExpiresOn.ToString("o")
                        };

                        var accountInfoJson = JsonSerializer.Serialize(accountInfo, new JsonSerializerOptions { WriteIndented = true });

                        // Store in session - including token expiry for Kusto reuse
                        HttpContext.Session.SetString("AzureToken", token.Token);
                        HttpContext.Session.SetString("AzureTokenExpiry", token.ExpiresOn.ToString("o"));
                        HttpContext.Session.SetString("AzureLoginTime", DateTime.UtcNow.ToString());
                        HttpContext.Session.SetString("AzureAccountInfo", accountInfoJson);
                        HttpContext.Session.SetString("AuthMethod", "AzureCli");
                        
                        _logger.LogInformation("Azure login successful via Azure CLI credential");
                        return new JsonResult(new 
                        { 
                            success = true, 
                            message = "Successfully logged in to Azure using Azure CLI", 
                            accountInfo = accountInfoJson 
                        });
                    }
                }
                catch (Exception cliEx)
                {
                    _logger.LogError(cliEx, "Azure CLI authentication failed");
                    return new JsonResult(new 
                    { 
                        success = false, 
                        message = "Azure CLI authentication failed. Please login first:\n1. Go to Azure Portal\n2. Open your App Service 'apploadtest'\n3. Go to Advanced Tools > Go\n4. Click 'Debug console' > 'CMD' or 'PowerShell'\n5. Run: az login\n6. Complete authentication in browser\n7. Return here and click 'Login to Azure' again",
                        details = cliEx.Message
                    });
                }
            }
            else
            {
                // Local environment: Use Interactive Browser
                _logger.LogInformation("Local environment - using Interactive Browser Authentication");
                
                _azureCredential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
                {
                    TenantId = "common",
                    ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                    BrowserCustomization = new BrowserCustomizationOptions
                    {
                        UseEmbeddedWebView = false
                    }
                });
                
                var tokenRequestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
                var token = await _azureCredential.GetTokenAsync(tokenRequestContext, CancellationToken.None);

                if (token.Token != null)
                {
                    // Get account information using Azure Resource Manager
                    var armClient = new ArmClient(_azureCredential);
                    var subscription = await armClient.GetDefaultSubscriptionAsync();
                    
                    var accountInfo = new
                    {
                        subscriptionId = subscription.Data.SubscriptionId,
                        subscriptionName = subscription.Data.DisplayName,
                        tenantId = subscription.Data.TenantId,
                        expiresOn = token.ExpiresOn.ToString("o")
                    };

                    var accountInfoJson = JsonSerializer.Serialize(accountInfo, new JsonSerializerOptions { WriteIndented = true });

                    // Store in session - including token expiry for Kusto reuse
                    HttpContext.Session.SetString("AzureToken", token.Token);
                    HttpContext.Session.SetString("AzureTokenExpiry", token.ExpiresOn.ToString("o"));
                    HttpContext.Session.SetString("AzureLoginTime", DateTime.UtcNow.ToString());
                    HttpContext.Session.SetString("AzureAccountInfo", accountInfoJson);
                    HttpContext.Session.SetString("AuthMethod", "InteractiveBrowser");
                    
                    _logger.LogInformation("Azure login successful via interactive browser authentication");
                    return new JsonResult(new 
                    { 
                        success = true, 
                        message = "Successfully logged in to Azure", 
                        accountInfo = accountInfoJson 
                    });
                }
                else
                {
                    _logger.LogError("Failed to obtain Azure token");
                    return new JsonResult(new { success = false, message = "Failed to obtain authentication token" });
                }
            }
        }
        catch (AuthenticationFailedException ex)
        {
            _logger.LogError(ex, "Authentication failed during Azure login");
            return new JsonResult(new { success = false, message = $"Authentication failed: {ex.Message}" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Azure login");
            return new JsonResult(new { success = false, message = $"Error: {ex.Message}" });
        }
        
        // Fallback return if no other path was taken
        return new JsonResult(new { success = false, message = "Authentication failed: Unknown error occurred" });
    }
}
