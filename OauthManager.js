'use strict'
/**
 * Implements Authorization Code Flow with Proof Key for Code Exchange (PKCE)
 * 
 * 1. Calling requestLogin() creates a cryptographically-random code_verifier and from this generates a code_challenge.
 * 2. Redirect the user to the Authorization Server (`oauthEndpoint`) along with the code_challenge.
 * 3. The Authorization Server redirects the user to a login and authorization prompt.
 * 4. The Authorization Server stores the code_challenge and redirects the user back to the application with an authorization code.
 * 5. We send a token request with this code and the code_verifier to the Authorization Server (`apiEndpoint`)
 * 6. The Authorization Server responds with an access token that is wrapped in the 'authorization' event
 * 
 * @emits login After receiving the access token
 * @emits logout After invalidating the access token
 * @emits authorization After recovering a stored token or requesting a new one
 */
class OauthLoginManager extends EventTarget {
    #token
    #code
    #oauthEndpoint
    #apiEndpoint
    #clientId
    #clientUrl = (() => {
        const url = new URL(location.href)
        url.search = ''
        return url.href
    })()

    isLoggedIn = () => this.#token != null


    constructor(oauthEndpoint, apiEndpoint, clientId) {
        super()
        this.#token = localStorage.getItem('accessToken')
        this.#code = localStorage.getItem('code')
        this.#oauthEndpoint = oauthEndpoint
        this.#clientId = clientId
        this.#apiEndpoint = apiEndpoint
    }

    async initialize() {
        this.isLoggedIn() || await this.#finishLoginProcedure()
        if (this.isLoggedIn()) {
            this.dispatchEvent(new CustomEvent('authorization', { detail: { token: this.#token } }))
        }
    }

    async #finishLoginProcedure() {
        this.#code ??= this.#retrieveCodeFromUrlParams()
        if (!this.#code) return // Initial state, login not requested previously, do nothing

        localStorage.setItem('code', this.#code)
        window.history.replaceState(null, document.title, this.#clientUrl)

        let codeVerifier = localStorage.getItem('codeVerifier')
        if (!codeVerifier) throw new Error('codeVerifier was lost')

        console.log('Found code', this.#code, 'Fetching new token')
        this.#token = await this.#fetchAuthToken(this.#code, codeVerifier)
        localStorage.setItem('accessToken', this.#token)
        console.log('Got fresh token', this.#token)
        this.dispatchEvent(new Event("login"))
    }

    #retrieveCodeFromUrlParams() {
        const urlParams = new URLSearchParams(window.location.search)
        return urlParams.get('code')
    }

    async #fetchAuthToken(code, codeVerifier) {
        const response = await fetch(this.#apiEndpoint + 'token', {
            method: 'POST', body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: this.#clientUrl,
                client_id: this.#clientId,
                code_verifier: codeVerifier
            })
        })
        if (!response.ok) throw new Error(`Error ${response.status} while requesting new API token.`)
        const json = await response.json()
        return json.access_token
    }

    async requestLogout() {
        console.log('Logging out')
        await fetch(this.#apiEndpoint + 'token', { headers, method: 'DELETE' })
        localStorage.clear()
        window.history.replaceState(null, document.title, this.#clientUrl)
        this.dispatchEvent(new Event('logout'))
    }

    async requestLogin() {
        const codeVerifier = this.#randomString(129)
        localStorage.setItem('codeVerifier', codeVerifier)
        const challenge = await this.#generateChallenge(codeVerifier)
        const url = new URL(this.#oauthEndpoint)
        url.searchParams.append('response_type', 'code')
        url.searchParams.append('redirect_uri', this.#clientUrl)
        url.searchParams.append('client_id', this.#clientId)
        url.searchParams.append('scope', '')
        url.searchParams.append('state', this.#randomString(33))
        url.searchParams.append('code_challenge', challenge)
        url.searchParams.append('code_challenge_method', 'S256')
        window.location = url
    }

    /* The following functions for PKCE are taken from
        https://github.com/crouchcd/pkce-challenge/blob/0b5a1a35b83bfb973ca492a2d8df9fe1b163d066/src/index.ts
    */
    #randomString(length) {
        const mask = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
        let result = '';
        const randomUints = crypto.getRandomValues(new Uint8Array(length));
        for (let i = 0; i < length; i++) {
            // cap the value of the randomIndex to mask.length - 1
            const randomIndex = randomUints[i] % mask.length;
            result += mask[randomIndex];
        }
        return result;
    }

    /** Generate a PKCE code challenge from a code verifier
     * @param code_verifier
     * @returns The base64 url encoded code challenge
     */
    async #generateChallenge(code_verifier) {
        const buffer = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(code_verifier)
        );
        // Generate base64url string
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\//g, '_')
            .replace(/\+/g, '-')
            .replace(/=/g, '');
    }
}