import { describe, expect, it, vi } from 'vitest';
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  credentialToJSON,
  decodeCreationOptions,
  decodeRequestOptions,
  responseToJSON,
  unwrapPublicKeyOptions,
} from './webauthn';

function bufferOf(text: string): ArrayBuffer {
  return new Uint8Array([...text].map(c => c.charCodeAt(0))).buffer;
}

function textOf(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map(b => String.fromCharCode(b)).join('');
}

describe('base64url helpers', () => {
  it('roundtrips arbitrary bytes', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0xfb, 0xff, 0xfe, 0x40, 0x7f]);
    const encoded = bufferToBase64Url(bytes.buffer);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(new Uint8Array(base64UrlToBuffer(encoded))).toEqual(bytes);
  });

  it('decodes unpadded input', () => {
    // btoa('challenge') = 'Y2hhbGxlbmdl' (no padding needed).
    expect(textOf(base64UrlToBuffer('Y2hhbGxlbmdl'))).toBe('challenge');
    // btoa('user') = 'dXNlcg==' — padding stripped on the wire.
    expect(textOf(base64UrlToBuffer('dXNlcg'))).toBe('user');
  });

  it('maps url-safe alphabet back to standard', () => {
    // 0xfb 0xff 0xfe exercises the +/ → -_ substitution both ways.
    const encoded = bufferToBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]).buffer);
    expect(encoded).toBe('-__-');
    expect(new Uint8Array(base64UrlToBuffer('-__-'))).toEqual(new Uint8Array([0xfb, 0xff, 0xfe]));
  });
});

describe('unwrapPublicKeyOptions', () => {
  it('unwraps camelCase and snake_case envelopes', () => {
    expect(unwrapPublicKeyOptions({ publicKey: { a: 1 } })).toEqual({ a: 1 });
    expect(unwrapPublicKeyOptions({ public_key: { b: 2 } })).toEqual({ b: 2 });
  });

  it('passes through bare options', () => {
    expect(unwrapPublicKeyOptions({ challenge: 'x' })).toEqual({ challenge: 'x' });
  });
});

describe('decodeCreationOptions', () => {
  it('decodes challenge, user.id and excludeCredentials', () => {
    const decoded = decodeCreationOptions({
      challenge: 'Y2hhbGxlbmdl',
      user: { id: 'dXNlcg', name: 'u', displayName: 'U' },
      excludeCredentials: [{ id: 'Y3JlZA', type: 'public-key' }],
    } as unknown as PublicKeyCredentialCreationOptions);

    expect(textOf(decoded.challenge as unknown as ArrayBuffer)).toBe('challenge');
    expect(textOf(decoded.user.id as unknown as ArrayBuffer)).toBe('user');
    expect(textOf(decoded.excludeCredentials![0].id as unknown as ArrayBuffer)).toBe('cred');
    // Non-binary fields are preserved.
    expect(decoded.user.name).toBe('u');
    expect(decoded.excludeCredentials![0].type).toBe('public-key');
  });

  it('rejects options without challenge or user.id', () => {
    expect(() =>
      decodeCreationOptions({ user: { id: 'dXNlcg' } } as unknown as PublicKeyCredentialCreationOptions),
    ).toThrow('Invalid WebAuthn creation options');
    expect(() =>
      decodeCreationOptions({ challenge: 'Y2hhbGxlbmdl' } as unknown as PublicKeyCredentialCreationOptions),
    ).toThrow('Invalid WebAuthn creation options');
  });
});

describe('decodeRequestOptions', () => {
  it('decodes challenge and allowCredentials', () => {
    const decoded = decodeRequestOptions({
      challenge: 'Y2hhbGxlbmdl',
      allowCredentials: [{ id: 'Y3JlZA', type: 'public-key' }],
    } as unknown as PublicKeyCredentialRequestOptions);

    expect(textOf(decoded.challenge as unknown as ArrayBuffer)).toBe('challenge');
    expect(textOf(decoded.allowCredentials![0].id as unknown as ArrayBuffer)).toBe('cred');
  });

  it('rejects options without a challenge', () => {
    expect(() => decodeRequestOptions({} as PublicKeyCredentialRequestOptions)).toThrow(
      'Invalid WebAuthn request options',
    );
  });
});

describe('credential serialization', () => {
  it('serializes an attestation response', () => {
    class FakeAttestation {
      constructor(
        public clientDataJSON: ArrayBuffer,
        public attestationObject: ArrayBuffer,
      ) {}
    }
    vi.stubGlobal('AuthenticatorAttestationResponse', FakeAttestation);

    const response = new FakeAttestation(bufferOf('client'), bufferOf('attest'));
    const json = responseToJSON(response as unknown as AuthenticatorResponse);
    expect(json).toEqual({
      clientDataJSON: bufferToBase64Url(bufferOf('client')),
      attestationObject: bufferToBase64Url(bufferOf('attest')),
    });
    vi.unstubAllGlobals();
  });

  it('serializes an assertion response, empty userHandle when absent', () => {
    // Anything that is not an attestation response takes the assertion path.
    vi.stubGlobal('AuthenticatorAttestationResponse', class {});
    const response = {
      clientDataJSON: bufferOf('client'),
      authenticatorData: bufferOf('auth'),
      signature: bufferOf('sig'),
      userHandle: null,
    };
    const json = responseToJSON(response as unknown as AuthenticatorResponse);
    expect(json).toEqual({
      clientDataJSON: bufferToBase64Url(bufferOf('client')),
      authenticatorData: bufferToBase64Url(bufferOf('auth')),
      signature: bufferToBase64Url(bufferOf('sig')),
      userHandle: '',
    });
    vi.unstubAllGlobals();
  });

  it('credentialToJSON encodes rawId and delegates the response', () => {
    vi.stubGlobal('AuthenticatorAttestationResponse', class {});
    const credential = {
      id: 'cred-id',
      rawId: bufferOf('raw'),
      type: 'public-key',
      response: {
        clientDataJSON: bufferOf('client'),
        authenticatorData: bufferOf('auth'),
        signature: bufferOf('sig'),
        userHandle: bufferOf('handle'),
      },
      getClientExtensionResults: () => ({}),
      authenticatorAttachment: 'cross-platform',
    };
    const json = credentialToJSON(credential as unknown as PublicKeyCredential);
    expect(json.id).toBe('cred-id');
    expect(json.rawId).toBe(bufferToBase64Url(bufferOf('raw')));
    expect(json.type).toBe('public-key');
    expect(json.authenticatorAttachment).toBe('cross-platform');
    const response = json.response as Record<string, string>;
    expect(response.userHandle).toBe(bufferToBase64Url(bufferOf('handle')));
    vi.unstubAllGlobals();
  });
});
