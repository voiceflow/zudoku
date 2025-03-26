import { type GoogleAuthenticationConfig } from "../../../config/config.js";
import { type AuthenticationProviderInitializer } from "../authentication.js";
import { AuthorizationError } from "../errors.js";
import { useAuthState } from "../state.js";
import {
  OpenIDAuthenticationProvider,
  type OpenIdProviderData,
} from "./openid.js";

const ISSUER_URL = "https://accounts.google.com";

export class GoogleAuthenticationProvider extends OpenIDAuthenticationProvider {
  constructor(config: GoogleAuthenticationConfig) {
    super({
      ...config,
      type: "openid",
      issuer: ISSUER_URL,
    });
  }

  onAuthorizationUrl = async (url: URL) => {
    url.searchParams.set("response_type", "token");
    url.searchParams.delete("code_challenge");
    url.searchParams.delete("code_challenge_method");
  };

  protected setTokensFromParams(params: URLSearchParams): void {
    const accessToken = params.get("access_token");
    if (!accessToken) {
      throw new AuthorizationError("No access_token in response");
    }

    const expiresIn = params.get("expires_in");
    if (!expiresIn) {
      throw new AuthorizationError("No expires_in in response");
    }

    const tokenType = params.get("token_type");
    if (!tokenType) {
      throw new AuthorizationError("No token_type in response");
    }

    const tokens: OpenIdProviderData = {
      accessToken,
      expiresOn: new Date(Date.now() + Number(expiresIn) * 1000),
      tokenType,
    };
    useAuthState.setState({
      providerData: tokens,
    });
  }

  handleCallback = async () => {
    const url = new URL(window.location.href);
    const params = new URLSearchParams(
      url.hash ? url.hash.substring(1) : undefined,
    );

    await this.validateState(params.get("state"));

    const authServer = await this.getAuthServer();

    this.setTokensFromParams(params);

    const accessToken = await this.getAccessToken();

    return this.finalizeAuthentication(authServer, accessToken);
  };
}

const googleAuth: AuthenticationProviderInitializer<
  GoogleAuthenticationConfig
> = (options) => new GoogleAuthenticationProvider(options);

export default googleAuth;
