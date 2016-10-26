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
        public static Uri GetOrganizationServiceUri(string url) => new Uri(url + "/XRMServices/2011/Organization.svc");

        // ReSharper disable once MemberCanBePrivate.Global
        public static Uri GetDiscoveryServiceUri(string url) => new Uri(url + "/XRMServices/2011/Discovery.svc");

        // ReSharper disable once UnusedMember.Global
        public static Configuration GetConfiguration(string url, string orgName = null)
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
                return
                    new Configuration
                        {
                            OrganizationUri = GetOrganizationServiceUri(url),
                            DiscoveryUri = GetDiscoveryServiceUri(url),
                            ServerAddress = url,
                            OrganizationName = orgName,
                            Credentials = authCredentials.ClientCredentials
                        };
            }

            return null;
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
            // ToDo: inside GetProxy similar logic already exists
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
            Type classType;
            var isOrganizationServiceRequest = typeof(TService) == typeof(IOrganizationService);
            var serviceUri = isOrganizationServiceRequest ? config.OrganizationUri : config.DiscoveryUri;

            var serviceManagement =
                    isOrganizationServiceRequest && config.OrganizationServiceManagement != null
                        ? (IServiceManagement<TService>)config.OrganizationServiceManagement
                        : ServiceConfigurationFactory.CreateManagement<TService>(serviceUri);

            config.EndpointType = serviceManagement.AuthenticationType;
            config.Credentials = FulfillCredentials(config);
            if (isOrganizationServiceRequest)
            {
                if (config.OrganizationTokenResponse == null)
                {
                    config.OrganizationServiceManagement = (IServiceManagement<IOrganizationService>)serviceManagement;
                }

                classType = typeof(ManagedTokenOrganizationServiceProxy);
            }
            else
            {
                if (config.DiscoveryTokenResponse == null)
                {
                    config.DiscoveryServiceManagement = (IServiceManagement<IDiscoveryService>)serviceManagement;
                }

                classType = typeof(ManagedTokenDiscoveryServiceProxy);
            }

            var authCredentials = new AuthenticationCredentials();
            if (string.IsNullOrWhiteSpace(config.UserPrincipalName))
            {
                authCredentials.ClientCredentials = config.Credentials;
            }
            else
            {
                authCredentials.UserPrincipalName = config.UserPrincipalName;
            }

            if (config.EndpointType != AuthenticationProviderType.ActiveDirectory)
            {
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

                // ReSharper disable once PossibleNullReferenceException
                return (TProxy)classType
                    .GetConstructor(new[] { typeof(IServiceManagement<TService>), typeof(SecurityTokenResponse) })
                    .Invoke(new object[] { serviceManagement, tokenCredentials.SecurityTokenResponse });
            }

            // ReSharper disable once PossibleNullReferenceException
            return (TProxy)classType
                .GetConstructor(new[] { typeof(IServiceManagement<TService>), typeof(ClientCredentials) })
                .Invoke(new object[] { serviceManagement, authCredentials.ClientCredentials });
        }

        private static ClientCredentials FulfillCredentials(Configuration config)
        {
            if (config.Credentials == null)
            {
                throw new Exception("Credentials not provided");
            }

            ClientCredentials credentials;
            switch (config.EndpointType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                    var clientCredential = config.Credentials.Windows.ClientCredential;
                    if (clientCredential.SecurePassword == null)
                    {
                        return null;
                    }

                    credentials = new ClientCredentials();
                    credentials.Windows.ClientCredential = new NetworkCredential(clientCredential.UserName, clientCredential.SecurePassword, clientCredential.Domain);

                    return credentials;
                case AuthenticationProviderType.LiveId:
                case AuthenticationProviderType.Federation:
                    credentials = new ClientCredentials();
                    credentials.UserName.UserName = config.Credentials.UserName.UserName;
                    credentials.UserName.Password = config.Credentials.UserName.Password;
                    return credentials;
                case AuthenticationProviderType.OnlineFederation:
                    config.UserPrincipalName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

                    return null;
                default:
                    return null;
            }
        }

        public class Configuration
        {
            public string ServerAddress { get; set; }

            public string OrganizationName { get; set; }

            public Uri DiscoveryUri { get; set; }

            public Uri OrganizationUri { get; set; }

            public Uri HomeRealmUri { get; set; }

            public ClientCredentials DeviceCredentials { get; set; }

            public ClientCredentials Credentials { get; set; }

            public AuthenticationProviderType EndpointType { get; set; }

            public string UserPrincipalName { get; set; }

            internal IServiceManagement<IOrganizationService> OrganizationServiceManagement { get; set; }

            internal SecurityTokenResponse OrganizationTokenResponse { get; set; }

            internal IServiceManagement<IDiscoveryService> DiscoveryServiceManagement { get; set; }

            internal SecurityTokenResponse DiscoveryTokenResponse { get; set; }

            public override bool Equals(object obj)
            {
                if (obj == null || GetType() != obj.GetType())
                {
                    return false;
                }

                var other = (Configuration)obj;
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
                var returnHashCode = ServerAddress.GetHashCode() ^ OrganizationName.GetHashCode() ^ EndpointType.GetHashCode();
                if (Credentials != null)
                {
                    if (EndpointType == AuthenticationProviderType.ActiveDirectory)
                    {
                        return returnHashCode ^
                               Credentials.Windows.ClientCredential.UserName.GetHashCode() ^
                               Credentials.Windows.ClientCredential.Domain.GetHashCode();
                    }

                    if (EndpointType == AuthenticationProviderType.LiveId)
                    {
                        return returnHashCode ^
                               Credentials.UserName.UserName.GetHashCode() ^
                               DeviceCredentials.UserName.UserName.GetHashCode() ^
                               DeviceCredentials.UserName.Password.GetHashCode();
                    }

                    return returnHashCode ^ Credentials.UserName.UserName.GetHashCode();
                }

                return returnHashCode;
            }
        }
    }
}
