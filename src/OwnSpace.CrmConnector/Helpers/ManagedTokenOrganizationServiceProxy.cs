using System;
using System.ServiceModel.Description;

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;

namespace OwnSpace.CrmConnector.Helpers
{
    internal sealed class ManagedTokenOrganizationServiceProxy : OrganizationServiceProxy
    {
        private readonly AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService> proxyManager;

        public ManagedTokenOrganizationServiceProxy(Uri serviceUri, ClientCredentials userCredentials)
            : base(serviceUri, null, userCredentials, null)
        {
            proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>(this);
        }

        public ManagedTokenOrganizationServiceProxy(IServiceManagement<IOrganizationService> serviceManagement, SecurityTokenResponse securityTokenRes)
            : base(serviceManagement, securityTokenRes)
        {
            proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>(this);
        }

        public ManagedTokenOrganizationServiceProxy(IServiceManagement<IOrganizationService> serviceManagement, ClientCredentials userCredentials)
            : base(serviceManagement, userCredentials)
        {
            proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>(this);
        }

        protected override SecurityTokenResponse AuthenticateDeviceCore()
        {
            return proxyManager.AuthenticateDevice();
        }

        protected override void AuthenticateCore()
        {
            proxyManager.ResetCredentials();
            base.AuthenticateCore();
        }

        protected override void ValidateAuthentication()
        {
            proxyManager.RenewTokenIfRequired();
            base.ValidateAuthentication();
        }
    }
}
