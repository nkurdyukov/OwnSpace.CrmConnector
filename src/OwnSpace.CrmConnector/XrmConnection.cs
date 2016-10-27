using System;
using System.Net;
using System.ServiceModel.Description;
using System.Windows.Forms;

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;
using Ookii.Dialogs;
using OwnSpace.CrmConnector.Helpers;

namespace OwnSpace.CrmConnector
{
    // ReSharper disable once UnusedMember.Global
    public static class XrmConnection
    {
        // ReSharper disable once MemberCanBePrivate.Global
        public static Uri GetOrganizationServiceUri(string url, string orgName = null)
        {
            url = url.EndsWith("/") ? url.Substring(0, url.Length - 1) : url;
            orgName = string.IsNullOrEmpty(orgName) ? string.Empty : $"/{orgName}";
            return new Uri($"{url}{orgName}/XRMServices/2011/Organization.svc");
        }

        // ReSharper disable once MemberCanBePrivate.Global
        public static Uri GetDiscoveryServiceUri(string url, string orgName = null)
        {
            url = url.EndsWith("/") ? url.Substring(0, url.Length - 1) : url;
            orgName = string.IsNullOrEmpty(orgName) ? string.Empty : $"/{orgName}";
            return new Uri($"{url}{orgName}/XRMServices/2011/Discovery.svc");
        }

        // ReSharper disable once UnusedMember.Global
        public static Configuration GetConfiguration(string url, string orgName = null, bool useDefaultCredentials = false)
        {
            ClientCredentials clientCredentials;
            if (useDefaultCredentials)
            {
                clientCredentials = new ClientCredentials();
                clientCredentials.Windows.ClientCredential = CredentialCache.DefaultNetworkCredentials;
            }
            else
            {
                var dialog =
                    new CredentialDialog
                        {
                            MainInstruction = "Please enter your CRM credentials",
                            ShowSaveCheckBox = true,
                            UseApplicationInstanceCredentialCache = true,
                            ShowUIForSavedCredentials = true,
                            Target = "OwnSpace_CRMSDK_",
                            WindowTitle = "Credentials dialog"
                        };
                var dialogResult = dialog.ShowDialog();
                if (dialogResult == DialogResult.OK)
                {
                    dialog.ConfirmCredentials(true);

                    var authCredentials = new AuthenticationCredentials();
                    authCredentials.ClientCredentials.UserName.UserName = dialog.Credentials.UserName;
                    authCredentials.ClientCredentials.UserName.Password = dialog.Credentials.Password;
                    clientCredentials = authCredentials.ClientCredentials;
                }
                else
                {
                    return null;
                }
            }

            var organizationServiceUri = GetOrganizationServiceUri(url, orgName);
            var discoveryServiceUri = GetDiscoveryServiceUri(url, orgName);
            var organizationServiceManagement = ServiceConfigurationFactory.CreateManagement<IOrganizationService>(organizationServiceUri);
            var discoveryServiceManagement = ServiceConfigurationFactory.CreateManagement<IDiscoveryService>(discoveryServiceUri);
            var config =
                new Configuration(url, orgName, organizationServiceManagement.AuthenticationType)
                    {
                        OrganizationUri = organizationServiceUri,
                        DiscoveryUri = discoveryServiceUri,
                        Credentials = clientCredentials,
                        OrganizationServiceManagement = organizationServiceManagement,
                        DiscoveryServiceManagement = discoveryServiceManagement
                    };

            config.Credentials = FulfillCredentials(config);

            return config;
        }

        // ReSharper disable once UnusedMember.Global
        public static OrganizationServiceProxy GetOrganizationServiceProxy(Configuration config, Action<OrganizationServiceProxy> enableProxyTypes = null)
        {
            OrganizationServiceProxy proxy;
            if (config.EndpointType == AuthenticationProviderType.ActiveDirectory &&
                config.OrganizationServiceManagement != null)
            {
                proxy = new ManagedTokenOrganizationServiceProxy(config.OrganizationServiceManagement, config.Credentials);
            }
            else
            {
                proxy = GetProxy<IOrganizationService, OrganizationServiceProxy>(config);
            }

            enableProxyTypes?.Invoke(proxy);

            return proxy;
        }

        // ReSharper disable once UnusedMember.Global
        public static DiscoveryServiceProxy GetDiscoveryServiceProxy(Configuration config)
        {
            // ToDo: inside GetProxy similar logic already exists - merge
            if (config.EndpointType == AuthenticationProviderType.ActiveDirectory &&
                config.DiscoveryServiceManagement != null)
            {
                return new ManagedTokenDiscoveryServiceProxy(config.DiscoveryServiceManagement, config.Credentials);
            }

            return GetProxy<IDiscoveryService, DiscoveryServiceProxy>(config);
        }

        private static TProxy GetProxy<TService, TProxy>(Configuration config)
            where TService : class
            where TProxy : ServiceProxy<TService>
        {
            // ToDo: avoid ugly type sniffing
            var isOrganizationServiceRequest = typeof(TService) == typeof(IOrganizationService);
            var classType = isOrganizationServiceRequest ? typeof(ManagedTokenOrganizationServiceProxy) : typeof(ManagedTokenDiscoveryServiceProxy);
            var serviceManagement = isOrganizationServiceRequest ? (IServiceManagement<TService>)config.OrganizationServiceManagement : (IServiceManagement<TService>)config.DiscoveryServiceManagement;
            var authCredentials = new AuthenticationCredentials();
            if (string.IsNullOrEmpty(config.UserPrincipalName))
            {
                authCredentials.ClientCredentials = config.Credentials;
            }
            else
            {
                authCredentials.UserPrincipalName = config.UserPrincipalName;
            }

            if (config.EndpointType == AuthenticationProviderType.ActiveDirectory)
            {
                // ReSharper disable once PossibleNullReferenceException
                return (TProxy)classType
                    .GetConstructor(new[] { typeof(IServiceManagement<TService>), typeof(ClientCredentials) })
                    .Invoke(new object[] { serviceManagement, authCredentials.ClientCredentials });
            }

            if (config.EndpointType == AuthenticationProviderType.LiveId)
            {
                authCredentials.SupportingCredentials =
                    new AuthenticationCredentials
                        {
                            ClientCredentials = config.DeviceCredentials
                        };
            }

            var tokenCredentials = serviceManagement.Authenticate(authCredentials);
            if (isOrganizationServiceRequest)
            {
                config.OrganizationTokenResponse = tokenCredentials.SecurityTokenResponse;
            }
            else
            {
                config.DiscoveryTokenResponse = tokenCredentials.SecurityTokenResponse;
            }

            // ReSharper disable once PossibleNullReferenceException
            return (TProxy)classType
                .GetConstructor(new[] { typeof(IServiceManagement<TService>), typeof(SecurityTokenResponse) })
                .Invoke(new object[] { serviceManagement, tokenCredentials.SecurityTokenResponse });
        }

        private static ClientCredentials FulfillCredentials(Configuration config)
        {
            if (config.Credentials == null)
            {
                throw new Exception("Credentials not provided");
            }

            switch (config.EndpointType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                     {
                         var clientCredential = config.Credentials.Windows.ClientCredential;
                         if (clientCredential.SecurePassword == null)
                         {
                             return null;
                         }

                         var credentials = new ClientCredentials();
                         credentials.Windows.ClientCredential = new NetworkCredential(clientCredential.UserName, clientCredential.SecurePassword, clientCredential.Domain);

                         return credentials;
                     }

                case AuthenticationProviderType.LiveId:
                case AuthenticationProviderType.Federation:
                    {
                        var credentials = new ClientCredentials();
                        credentials.UserName.UserName = config.Credentials.UserName.UserName;
                        credentials.UserName.Password = config.Credentials.UserName.Password;

                        return credentials;
                    }

                case AuthenticationProviderType.OnlineFederation:
                    config.UserPrincipalName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

                    return null;
                case AuthenticationProviderType.None:
                    return null;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        public class Configuration
        {
            internal Configuration(string serverAddress, string organizationName, AuthenticationProviderType endpointType)
                : this()
            {
                ServerAddress = serverAddress;
                OrganizationName = organizationName;
                EndpointType = endpointType;
            }

            private Configuration()
            {
            }

            public string ServerAddress { get; }

            public string OrganizationName { get; }

            public Uri DiscoveryUri { get; internal set; }

            public Uri OrganizationUri { get; internal set; }

            public Uri HomeRealmUri { get; set; }

            public ClientCredentials DeviceCredentials { get; set; }

            public ClientCredentials Credentials { get; internal set; }

            public AuthenticationProviderType EndpointType { get; }

            public string UserPrincipalName { get; internal set; }

            public IServiceManagement<IOrganizationService> OrganizationServiceManagement { get; internal set; }

            public SecurityTokenResponse OrganizationTokenResponse { get; internal set; }

            public IServiceManagement<IDiscoveryService> DiscoveryServiceManagement { get; internal set; }

            public SecurityTokenResponse DiscoveryTokenResponse { get; internal set; }

            public override bool Equals(object obj)
            {
                var other = obj as Configuration;
                if (other == null)
                {
                    return false;
                }

                if (!ServerAddress.Equals(other.ServerAddress, StringComparison.InvariantCultureIgnoreCase))
                {
                    return false;
                }

                if (!OrganizationName.Equals(other.OrganizationName, StringComparison.InvariantCultureIgnoreCase))
                {
                    return false;
                }

                if (EndpointType != other.EndpointType)
                {
                    return false;
                }

                if (Credentials == null || other.Credentials == null)
                {
                    return true;
                }

                switch (EndpointType)
                {
                    case AuthenticationProviderType.ActiveDirectory:
                        if (!Credentials.Windows.ClientCredential.Domain.Equals(other.Credentials.Windows.ClientCredential.Domain, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return false;
                        }

                        if (!Credentials.Windows.ClientCredential.UserName.Equals(other.Credentials.Windows.ClientCredential.UserName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return false;
                        }

                        return true;
                    case AuthenticationProviderType.LiveId:
                        if (!Credentials.UserName.UserName.Equals(other.Credentials.UserName.UserName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return false;
                        }

                        if (!DeviceCredentials.UserName.UserName.Equals(other.DeviceCredentials.UserName.UserName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return false;
                        }

                        if (!DeviceCredentials.UserName.Password.Equals(other.DeviceCredentials.UserName.Password, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return false;
                        }

                        return true;
                    case AuthenticationProviderType.None:
                    case AuthenticationProviderType.Federation:
                    case AuthenticationProviderType.OnlineFederation:
                        return Credentials.UserName.UserName.Equals(other.Credentials.UserName.UserName, StringComparison.InvariantCultureIgnoreCase);

                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }

            public override int GetHashCode()
            {
                var hashCode = ServerAddress.GetHashCode() ^ OrganizationName.GetHashCode() ^ EndpointType.GetHashCode();
                // ReSharper disable once NonReadonlyMemberInGetHashCode
                if (Credentials != null)
                {
                    if (EndpointType == AuthenticationProviderType.ActiveDirectory)
                    {
                        return hashCode ^
                               Credentials.Windows.ClientCredential.UserName.GetHashCode() ^
                               Credentials.Windows.ClientCredential.Domain.GetHashCode();
                    }

                    if (EndpointType == AuthenticationProviderType.LiveId)
                    {
                        return hashCode ^
                               Credentials.UserName.UserName.GetHashCode() ^
                               DeviceCredentials.UserName.UserName.GetHashCode() ^
                               DeviceCredentials.UserName.Password.GetHashCode();
                    }

                    return hashCode ^ Credentials.UserName.UserName.GetHashCode();
                }

                return hashCode;
            }
        }
    }
}
