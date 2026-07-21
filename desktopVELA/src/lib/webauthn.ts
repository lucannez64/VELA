// Shared WebAuthn encode/decode helpers for the hand-rolled ceremonies used
// by recovery-key setup (navigator.credentials.create) and account recovery
// (navigator.credentials.get). No WebAuthn library is used on desktop — the
// server's options/response shapes are the standard WebAuthn JSON dictionary
// with base64url-encoded binary fields.

export function unwrapPublicKeyOptions(response: any): any {
  return response?.publicKey ?? response?.public_key ?? response;
}

export function decodeCreationOptions(
  options: PublicKeyCredentialCreationOptions
): PublicKeyCredentialCreationOptions {
  if (!options?.challenge || !options?.user?.id) {
    throw new Error('Invalid WebAuthn creation options from server');
  }

  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as unknown as string),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id as unknown as string),
    },
    excludeCredentials: options.excludeCredentials?.map(credential => ({
      ...credential,
      id: base64UrlToBuffer(credential.id as unknown as string),
    })),
  };
}

export function decodeRequestOptions(
  options: PublicKeyCredentialRequestOptions
): PublicKeyCredentialRequestOptions {
  if (!options?.challenge) {
    throw new Error('Invalid WebAuthn request options from server');
  }

  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as unknown as string),
    allowCredentials: options.allowCredentials?.map(credential => ({
      ...credential,
      id: base64UrlToBuffer(credential.id as unknown as string),
    })),
  };
}

export function credentialToJSON(credential: PublicKeyCredential): Record<string, unknown> {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: responseToJSON(credential.response),
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  };
}

export function responseToJSON(response: AuthenticatorResponse): Record<string, string> {
  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
    };
  }

  return {
    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    authenticatorData: bufferToBase64Url((response as AuthenticatorAssertionResponse).authenticatorData),
    signature: bufferToBase64Url((response as AuthenticatorAssertionResponse).signature),
    userHandle: (response as AuthenticatorAssertionResponse).userHandle
      ? bufferToBase64Url((response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer)
      : '',
  };
}

export function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
