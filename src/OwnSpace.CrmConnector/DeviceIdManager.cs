using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace OwnSpace.CrmConnector
{
    public enum DeviceRegistrationErrorCode
    {
        /// <summary>
        /// Unspecified or Unknown Error occurred
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Interface Disabled
        /// </summary>
        InterfaceDisabled = 1,

        /// <summary>
        /// Invalid Request Format
        /// </summary>
        InvalidRequestFormat = 3,

        /// <summary>
        /// Unknown Client Version
        /// </summary>
        UnknownClientVersion = 4,

        /// <summary>
        /// Blank Password
        /// </summary>
        BlankPassword = 6,

        /// <summary>
        /// Missing Device User Name or Password
        /// </summary>
        MissingDeviceUserNameOrPassword = 7,

        /// <summary>
        /// Invalid Parameter Syntax
        /// </summary>
        InvalidParameterSyntax = 8,

        /// <summary>
        /// Invalid Characters are used in the device credentials.
        /// </summary>
        InvalidCharactersInCredentials = 9,

        /// <summary>
        /// Internal Error
        /// </summary>
        InternalError = 11,

        /// <summary>
        /// Device Already Exists
        /// </summary>
        DeviceAlreadyExists = 13
    }

    public static class DeviceIdManager
    {
        private static readonly Random RandomInstance = new Random();

        public const int MaxDeviceNameLength = 24;

        public const int MaxDevicePasswordLength = 24;

        static DeviceIdManager()
        {
            PersistToFile = true;
        }

        public static bool PersistToFile { get; set; }

        public static bool PersistIfDeviceAlreadyExists { get; set; }

        public static ClientCredentials LoadOrRegisterDevice(string deviceName, string devicePassword)
        {
            return LoadOrRegisterDevice(null, deviceName, devicePassword);
        }

        public static ClientCredentials LoadOrRegisterDevice(Uri issuerUri = null)
        {
            return LoadOrRegisterDevice(issuerUri, null, null);
        }

        public static ClientCredentials LoadOrRegisterDevice(Uri issuerUri, string deviceName, string devicePassword)
        {
            var credentials = LoadDeviceCredentials(issuerUri);
            if (null == credentials)
            {
                credentials = RegisterDevice(Guid.NewGuid(), issuerUri, deviceName, devicePassword);
            }

            return credentials;
        }

        public static ClientCredentials RegisterDevice()
        {
            return RegisterDevice(Guid.NewGuid());
        }

        public static ClientCredentials RegisterDevice(Guid applicationId, Uri issuerUri = (Uri)null)
        {
            return RegisterDevice(applicationId, issuerUri, null, null);
        }

        public static ClientCredentials RegisterDevice(Guid applicationId, string deviceName, string devicePassword)
        {
            return RegisterDevice(applicationId, null, deviceName, devicePassword);
        }

        public static ClientCredentials RegisterDevice(Guid applicationId, Uri issuerUri, string deviceName, string devicePassword)
        {
            if (string.IsNullOrEmpty(deviceName) && !PersistToFile)
            {
                throw new ArgumentNullException(nameof(deviceName), "If PersistToFile is false, then deviceName must be specified.");
            }

            if (string.IsNullOrEmpty(deviceName) != string.IsNullOrEmpty(devicePassword))
            {
                throw new ArgumentNullException(nameof(deviceName), "Either deviceName/devicePassword should both be specified or they should be null.");
            }

            var device = GenerateDevice(deviceName, devicePassword);
            return RegisterDevice(applicationId, issuerUri, device);
        }

        public static ClientCredentials LoadDeviceCredentials(Uri issuerUri = null)
        {
            //If the credentials should not be persisted to a file, then they won't be present on the disk.
            if (!PersistToFile)
            {
                return null;
            }

            var environment = DiscoverEnvironmentInternal(issuerUri);

            var device = ReadExistingDevice(environment);
            if (null == device || null == device.User)
            {
                return null;
            }

            return device.User.ToClientCredentials();
        }

        public static string DiscoverEnvironment(Uri issuerUri)
        {
            return DiscoverEnvironmentInternal(issuerUri).Environment;
        }

        private static EnvironmentConfiguration DiscoverEnvironmentInternal(Uri issuerUri)
        {
            if (issuerUri == null)
            {
                return new EnvironmentConfiguration(EnvironmentType.LiveDeviceID, "login.live.com", null);
            }

            var searchList =
                new Dictionary<EnvironmentType, string>
                    {
                        { EnvironmentType.LiveDeviceID, "login.live" },
                        { EnvironmentType.OrgDeviceID, "login.microsoftonline" }
                    };

            foreach (var searchPair in searchList)
            {
                if (issuerUri.Host.Length > searchPair.Value.Length &&
                    issuerUri.Host.StartsWith(searchPair.Value, StringComparison.OrdinalIgnoreCase))
                {
                    var environment = issuerUri.Host.Substring(searchPair.Value.Length);

                    if (environment[0] == '-')
                    {
                        var separatorIndex = environment.IndexOf('.', 1);
                        environment = separatorIndex != -1 ? environment.Substring(1, separatorIndex - 1) : null;
                    }
                    else
                    {
                        environment = null;
                    }

                    return new EnvironmentConfiguration(searchPair.Key, issuerUri.Host, environment);
                }
            }

            return new EnvironmentConfiguration(EnvironmentType.LiveDeviceID, issuerUri.Host, null);
        }

        private static void Serialize<T>(Stream stream, T value)
        {
            var serializer = new XmlSerializer(typeof(T), string.Empty);

            var xmlNamespaces = new XmlSerializerNamespaces();
            xmlNamespaces.Add(string.Empty, string.Empty);

            serializer.Serialize(stream, value, xmlNamespaces);
        }

        private static T Deserialize<T>(string operationName, Stream stream)
        {
            using (var reader = new StreamReader(stream))
            {
                return Deserialize<T>(operationName, reader.ReadToEnd());
            }
        }

        private static T Deserialize<T>(string operationName, string xml)
        {
            using (var reader = new StringReader(xml))
            {
                try
                {
                    var serializer = new XmlSerializer(typeof(T), string.Empty);
                    return (T)serializer.Deserialize(reader);
                }
                catch (InvalidOperationException ex)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unable to Deserialize XML (Operation = {0}):{1}{2}", operationName, Environment.NewLine, xml), ex);
                }
            }
        }

        private static FileInfo GetDeviceFile(EnvironmentConfiguration environment)
        {
            return new FileInfo(string.Format(CultureInfo.InvariantCulture, LiveIdConstants.FileNameFormat, environment.Type, string.IsNullOrEmpty(environment.Environment) ? null : "-" + environment.Environment.ToUpperInvariant()));
        }

        private static ClientCredentials RegisterDevice(Guid applicationId, Uri issuerUri, LiveDevice device)
        {
            var environment = DiscoverEnvironmentInternal(issuerUri);
            var request = new DeviceRegistrationRequest(applicationId, device);
            var url = string.Format(CultureInfo.InvariantCulture, LiveIdConstants.RegistrationEndpointUriFormat, environment.HostName);
            var response = ExecuteRegistrationRequest(url, request);
            if (!response.IsSuccess)
            {
                var throwException = true;
                if (DeviceRegistrationErrorCode.DeviceAlreadyExists == response.Error.RegistrationErrorCode)
                {
                    if (!PersistToFile)
                    {
                        return device.User.ToClientCredentials();
                    }

                    if (PersistIfDeviceAlreadyExists)
                    {
                        throwException = false;
                    }
                }

                if (throwException)
                {
                    throw new DeviceRegistrationFailedException(response.Error.RegistrationErrorCode, response.ErrorSubCode);
                }
            }

            if (PersistToFile || PersistIfDeviceAlreadyExists)
            {
                WriteDevice(environment, device);
            }

            return device.User.ToClientCredentials();
        }

        private static LiveDevice GenerateDevice(string deviceName, string devicePassword)
        {
            var userNameCredentials =
                string.IsNullOrEmpty(deviceName)
                ? GenerateDeviceUserName()
                : new DeviceUserName
                      {
                          DeviceName = deviceName,
                          DecryptedPassword = devicePassword
                      };

            return new LiveDevice
                       {
                           User = userNameCredentials,
                           Version = 1
                       };
        }

        private static LiveDevice ReadExistingDevice(EnvironmentConfiguration environment)
        {
            var file = GetDeviceFile(environment);
            if (!file.Exists)
            {
                return null;
            }

            using (var stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                return Deserialize<LiveDevice>("Loading Device Credentials from Disk", stream);
            }
        }

        private static void WriteDevice(EnvironmentConfiguration environment, LiveDevice device)
        {
            var file = GetDeviceFile(environment);
            if (file.Directory != null && !file.Directory.Exists)
            {
                file.Directory.Create();
            }

            using (var stream = file.Open(FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                Serialize(stream, device);
            }
        }

        private static DeviceRegistrationResponse ExecuteRegistrationRequest(string url, DeviceRegistrationRequest registrationRequest)
        {
            var request = WebRequest.Create(url);
            request.ContentType = "application/soap+xml; charset=UTF-8";
            request.Method = "POST";
            request.Timeout = 180000;

            // ToDo: async
            using (var stream = request.GetRequestStream())
            {
                Serialize(stream, registrationRequest);
            }

            try
            {
                using (var response = request.GetResponse())
                using (var stream = response.GetResponseStream())
                {
                    return Deserialize<DeviceRegistrationResponse>("Deserializing Registration Response", stream);
                }
            }
            catch (WebException ex)
            {
                System.Diagnostics.Trace.TraceError("Microsoft account Device Registration Failed (HTTP Code: {0}): {1}", ex.Status, ex.Message);

                if (ex.Response != null)
                {
                    using (var stream = ex.Response.GetResponseStream())
                    {
                        return Deserialize<DeviceRegistrationResponse>("Deserializing Failed Registration Response", stream);
                    }
                }

                throw;
            }
        }

        private static DeviceUserName GenerateDeviceUserName()
        {
            return
                new DeviceUserName
                    {
                        DeviceName = GenerateRandomString(LiveIdConstants.ValidDeviceNameCharacters, MaxDeviceNameLength),
                        DecryptedPassword = GenerateRandomString(LiveIdConstants.ValidDevicePasswordCharacters, MaxDevicePasswordLength)
                    };
        }

        private static string GenerateRandomString(string characterSet, int count)
        {
            var value = new char[count];
            var set = characterSet.ToCharArray();

            lock (RandomInstance)
            {
                for (var i = 0; i < count; i++)
                {
                    value[i] = set[RandomInstance.Next(0, set.Length)];
                }
            }

            return new string(value);
        }

        private enum EnvironmentType
        {
            LiveDeviceID,
            OrgDeviceID
        }

        private sealed class EnvironmentConfiguration
        {
            public EnvironmentConfiguration(EnvironmentType type, string hostName, string environment)
            {
                if (string.IsNullOrWhiteSpace(hostName))
                {
                    throw new ArgumentNullException(nameof(hostName));
                }

                Type = type;
                HostName = hostName;
                Environment = environment;
            }

            public EnvironmentType Type { get; private set; }

            public string HostName { get; private set; }

            public string Environment { get; private set; }
        }

        private static class LiveIdConstants
        {
            public const string RegistrationEndpointUriFormat = @"https://{0}/ppsecure/DeviceAddCredential.srf";

            public static readonly string FileNameFormat = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "LiveDeviceID"), "{0}{1}.xml");

            public const string ValidDeviceNameCharacters = "0123456789abcdefghijklmnopqrstuvqxyz";

            public const string ValidDevicePasswordCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^*()-_=+;,./?`~";
        }
    }

    [Serializable]
    public sealed class DeviceRegistrationFailedException : Exception
    {
        /// <summary>
        /// Construct an instance of the DeviceRegistrationFailedException class
        /// </summary>
        /// <param name="code">Error code that occurred</param>
        /// <param name="subCode">Subcode that occurred</param>
        public DeviceRegistrationFailedException(DeviceRegistrationErrorCode code, string subCode)
            : this(code, subCode, null)
        {
        }

        /// <summary>
        /// Construct an instance of the DeviceRegistrationFailedException class
        /// </summary>
        /// <param name="code">Error code that occurred</param>
        /// <param name="subCode">Subcode that occurred</param>
        /// <param name="innerException">Inner exception</param>
        private DeviceRegistrationFailedException(DeviceRegistrationErrorCode code, string subCode, Exception innerException)
            : base(string.Concat(code.ToString(), ": ", subCode), innerException)
        {
            RegistrationErrorCode = code;
        }

        /// <summary>
        /// Construct an instance of the DeviceRegistrationFailedException class
        /// </summary>
        /// <param name="si"></param>
        /// <param name="sc"></param>
        private DeviceRegistrationFailedException(SerializationInfo si, StreamingContext sc)
            : base(si, sc)
        {
        }

        /// <summary>
        /// Error code that occurred during registration
        /// </summary>
        public DeviceRegistrationErrorCode RegistrationErrorCode { get; private set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("DeviceAddRequest")]
    public sealed class DeviceRegistrationRequest
    {
        public DeviceRegistrationRequest()
        {
        }

        public DeviceRegistrationRequest(Guid applicationId, LiveDevice device)
            : this()
        {
            if (null == device)
            {
                throw new ArgumentNullException(nameof(device));
            }

            ClientInfo = new DeviceRegistrationClientInfo { ApplicationId = applicationId, Version = "1.0" };
            Authentication = new DeviceRegistrationAuthentication
            {
                MemberName = device.User.DeviceId,
                Password = device.User.DecryptedPassword
            };
        }

        [XmlElement("ClientInfo")]
        public DeviceRegistrationClientInfo ClientInfo { get; set; }

        [XmlElement("Authentication")]
        public DeviceRegistrationAuthentication Authentication { get; set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("ClientInfo")]
    public sealed class DeviceRegistrationClientInfo
    {
        [XmlAttribute("name")]
        public Guid ApplicationId { get; set; }

        [XmlAttribute("version")]
        public string Version { get; set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("Authentication")]
    public sealed class DeviceRegistrationAuthentication
    {
        [XmlElement("Membername")]
        public string MemberName { get; set; }

        [XmlElement("Password")]
        public string Password { get; set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("DeviceAddResponse")]
    public sealed class DeviceRegistrationResponse
    {
        [XmlElement("success")]
        public bool IsSuccess { get; set; }

        [XmlElement("puid")]
        public string Puid { get; set; }

        [XmlElement("Error")]
        public DeviceRegistrationResponseError Error { get; set; }

        [XmlElement("ErrorSubcode")]
        public string ErrorSubCode { get; set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("Error")]
    public sealed class DeviceRegistrationResponseError
    {
        private string _code;

        [XmlAttribute("Code")]
        public string Code
        {
            get
            {
                return _code;
            }

            set
            {
                _code = value;

                //Parse the error code
                if (!string.IsNullOrEmpty(value))
                {
                    //Parse the error code
                    if (value.StartsWith("dc", StringComparison.Ordinal))
                    {
                        int code;
                        if (int.TryParse(value.Substring(2), NumberStyles.Integer,
                            CultureInfo.InvariantCulture, out code) &&
                            Enum.IsDefined(typeof(DeviceRegistrationErrorCode), code))
                        {
                            RegistrationErrorCode = (DeviceRegistrationErrorCode)Enum.ToObject(
                                typeof(DeviceRegistrationErrorCode), code);
                        }
                    }
                }
            }
        }

        [XmlIgnore]
        public DeviceRegistrationErrorCode RegistrationErrorCode { get; private set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    [XmlRoot("Data")]
    public sealed class LiveDevice
    {
        [XmlAttribute("version")]
        public int Version { get; set; }

        [XmlElement("User")]
        public DeviceUserName User { get; set; }

        [SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode", Justification = "This is required for proper XML Serialization")]
        [XmlElement("Token")]
        public XmlNode Token { get; set; }

        [XmlElement("Expiry")]
        public string Expiry { get; set; }

        [XmlElement("ClockSkew")]
        public string ClockSkew { get; set; }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class DeviceUserName
    {
        private string _encryptedPassword;

        private string _decryptedPassword;

        private bool _encryptedValueIsUpdated;

        private const string UserNamePrefix = "11";

        public DeviceUserName()
        {
            UserNameType = "Logical";
        }

        [XmlAttribute("username")]
        public string DeviceName { get; set; }

        [XmlAttribute("type")]
        public string UserNameType { get; set; }

        [XmlElement("Pwd")]
        public string EncryptedPassword
        {
            get
            {
                ThrowIfNoEncryption();

                if (!_encryptedValueIsUpdated)
                {
                    _encryptedPassword = Encrypt(_decryptedPassword);
                    _encryptedValueIsUpdated = true;
                }

                return _encryptedPassword;
            }

            set
            {
                ThrowIfNoEncryption();
                UpdateCredentials(value, null);
            }
        }

        public string DeviceId
        {
            get
            {
                return UserNamePrefix + DeviceName;
            }
        }

        [XmlIgnore]
        public string DecryptedPassword
        {
            get
            {
                return _decryptedPassword;
            }

            set
            {
                UpdateCredentials(null, value);
            }
        }

        private bool IsEncryptionEnabled
        {
            get
            {
                //If the object is not going to be persisted to a file, then the value does not need to be encrypted. This is extra
                //overhead and will not function in partial trust.
                return DeviceIdManager.PersistToFile;
            }
        }

        public ClientCredentials ToClientCredentials()
        {
            var credentials = new ClientCredentials();
            credentials.UserName.UserName = DeviceId;
            credentials.UserName.Password = DecryptedPassword;

            return credentials;
        }

        private static string Encrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            var encryptedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(encryptedBytes);
        }

        private static string Decrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            var decryptedBytes = ProtectedData.Unprotect(Convert.FromBase64String(value), null, DataProtectionScope.CurrentUser);
            return decryptedBytes.Length == 0 ? null : Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length);
        }

        private void ThrowIfNoEncryption()
        {
            if (!IsEncryptionEnabled)
            {
                throw new NotSupportedException("Not supported when DeviceIdManager.UseEncryptionApis is false.");
            }
        }

        private void UpdateCredentials(string encryptedValue, string decryptedValue)
        {
            var isValueUpdated = false;
            if (string.IsNullOrEmpty(encryptedValue) && string.IsNullOrEmpty(decryptedValue))
            {
                isValueUpdated = true;
            }
            else if (string.IsNullOrEmpty(encryptedValue))
            {
                if (IsEncryptionEnabled)
                {
                    encryptedValue = Encrypt(decryptedValue);
                    isValueUpdated = true;
                }
                else
                {
                    encryptedValue = null;
                    isValueUpdated = false;
                }
            }
            else
            {
                ThrowIfNoEncryption();

                decryptedValue = Decrypt(encryptedValue);
                isValueUpdated = true;
            }

            _encryptedPassword = encryptedValue;
            _decryptedPassword = decryptedValue;
            _encryptedValueIsUpdated = isValueUpdated;
        }
    }
}
