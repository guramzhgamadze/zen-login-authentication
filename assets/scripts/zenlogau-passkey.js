/**
 * Zen Login & Authentication — Passkeys (WebAuthn) frontend.
 *
 * Talks to admin-ajax. The server (lbuchs/WebAuthn) encodes binary args as
 * "=?BINARY?B?<base64>?=" strings; we turn those into ArrayBuffers before
 * calling the WebAuthn API, and send binary responses back as standard base64.
 */
( function () {
	'use strict';

	var cfg = window.zenlogauPasskey || {};
	var i18n = cfg.i18n || {};

	function supported() {
		return !! ( window.PublicKeyCredential && navigator.credentials && navigator.credentials.create );
	}

	/* ---- binary <-> base64 helpers (match the PHP library's contract) ---- */
	function recursiveDecode( obj ) {
		var prefix = '=?BINARY?B?';
		var suffix = '?=';
		if ( obj === null || typeof obj !== 'object' ) {
			return;
		}
		Object.keys( obj ).forEach( function ( key ) {
			var val = obj[ key ];
			if ( typeof val === 'string' ) {
				if ( val.substring( 0, prefix.length ) === prefix &&
					val.substring( val.length - suffix.length ) === suffix ) {
					var b64 = val.substring( prefix.length, val.length - suffix.length );
					var bin = window.atob( b64 );
					var bytes = new Uint8Array( bin.length );
					for ( var i = 0; i < bin.length; i++ ) {
						bytes[ i ] = bin.charCodeAt( i );
					}
					obj[ key ] = bytes.buffer;
				}
			} else if ( typeof val === 'object' ) {
				recursiveDecode( val );
			}
		} );
	}

	function bufToB64( buffer ) {
		var bytes = new Uint8Array( buffer );
		var binary = '';
		for ( var i = 0; i < bytes.byteLength; i++ ) {
			binary += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa( binary );
	}

	/* ---- transport ---- */
	function post( action, fields ) {
		var body = new URLSearchParams();
		body.append( 'action', action );
		if ( cfg.nonce ) {
			body.append( 'nonce', cfg.nonce );
		}
		Object.keys( fields || {} ).forEach( function ( k ) {
			if ( fields[ k ] !== undefined && fields[ k ] !== null ) {
				body.append( k, fields[ k ] );
			}
		} );
		return window.fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		} ).then( function ( r ) { return r.json(); } );
	}

	function setStatus( el, msg, isError ) {
		if ( ! el ) {
			return;
		}
		el.textContent = msg || '';
		el.classList.toggle( 'fauth-passkey-error', !! isError );
	}

	function statusFor( node ) {
		var wrap = node.closest( '.fauth' );
		return wrap ? wrap.querySelector( '.fauth-passkey-status' ) : null;
	}

	/* ---- registration (Account page) ---- */
	function register( btn ) {
		var status = statusFor( btn );
		if ( ! supported() ) {
			setStatus( status, i18n.unsupported, true );
			return;
		}
		var label = window.prompt( i18n.name_prompt, '' );
		if ( label === null ) {
			setStatus( status, i18n.cancelled );
			return;
		}
		setStatus( status, i18n.registering );
		btn.disabled = true;

		post( 'zenlogau_passkey_register_options', {} ).then( function ( res ) {
			if ( ! res || ! res.success || ! res.data || ! res.data.publicKey ) {
				throw new Error( ( res && res.data && res.data.message ) || i18n.reg_fail );
			}
			var args = res.data;
			recursiveDecode( args );
			return navigator.credentials.create( args );
		} ).then( function ( cred ) {
			return post( 'zenlogau_passkey_register_verify', {
				label: label,
				clientDataJSON: bufToB64( cred.response.clientDataJSON ),
				attestationObject: bufToB64( cred.response.attestationObject )
			} );
		} ).then( function ( res ) {
			if ( ! res || ! res.success ) {
				throw new Error( ( res && res.data && res.data.message ) || i18n.reg_fail );
			}
			var list = document.querySelector( '.fauth-passkeys-list' );
			if ( list && res.data.list ) {
				list.innerHTML = res.data.list;
			}
			setStatus( status, res.data.message || i18n.reg_ok );
		} ).catch( function ( err ) {
			setStatus( status, friendly( err, i18n.reg_fail ), true );
		} ).finally( function () {
			btn.disabled = false;
		} );
	}

	/* ---- removal ---- */
	function remove( btn ) {
		var status = statusFor( btn );
		if ( ! window.confirm( i18n.confirm_del ) ) {
			return;
		}
		btn.disabled = true;
		post( 'zenlogau_passkey_delete', { credential: btn.getAttribute( 'data-credential' ) } ).then( function ( res ) {
			if ( ! res || ! res.success ) {
				throw new Error( ( res && res.data && res.data.message ) || '' );
			}
			var list = document.querySelector( '.fauth-passkeys-list' );
			if ( list && res.data.list ) {
				list.innerHTML = res.data.list;
			}
			setStatus( status, res.data.message );
		} ).catch( function ( err ) {
			setStatus( status, friendly( err, '' ), true );
			btn.disabled = false;
		} );
	}

	/* ---- passwordless login ---- */
	function signIn( btn ) {
		var status = statusFor( btn );
		if ( ! supported() ) {
			setStatus( status, i18n.unsupported, true );
			return;
		}
		setStatus( status, i18n.signing_in );
		btn.disabled = true;
		var handle;

		post( 'zenlogau_passkey_login_options', {} ).then( function ( res ) {
			if ( ! res || ! res.success || ! res.data || ! res.data.publicKey ) {
				throw new Error( ( res && res.data && res.data.message ) || i18n.login_fail );
			}
			handle = res.data.handle;
			var args = { publicKey: res.data.publicKey };
			recursiveDecode( args );
			return navigator.credentials.get( args );
		} ).then( function ( cred ) {
			return post( 'zenlogau_passkey_login_verify', {
				handle: handle,
				id: bufToB64( cred.rawId ),
				clientDataJSON: bufToB64( cred.response.clientDataJSON ),
				authenticatorData: bufToB64( cred.response.authenticatorData ),
				signature: bufToB64( cred.response.signature ),
				userHandle: cred.response.userHandle ? bufToB64( cred.response.userHandle ) : '',
				redirect_to: btn.getAttribute( 'data-redirect' ) || ''
			} );
		} ).then( function ( res ) {
			if ( ! res || ! res.success ) {
				throw new Error( ( res && res.data && res.data.message ) || i18n.login_fail );
			}
			window.location.assign( res.data.redirect || window.location.href );
		} ).catch( function ( err ) {
			setStatus( status, friendly( err, i18n.login_fail ), true );
			btn.disabled = false;
		} );
	}

	function friendly( err, fallback ) {
		if ( err && ( err.name === 'NotAllowedError' || err.name === 'AbortError' ) ) {
			return i18n.cancelled || fallback;
		}
		return ( err && err.message ) ? err.message : fallback;
	}

	/* ---- wire up (event delegation, survives AJAX-rebuilt lists) ---- */
	document.addEventListener( 'click', function ( e ) {
		var t = e.target;
		if ( ! t || ! t.closest ) {
			return;
		}
		var add = t.closest( '.fauth-passkey-add' );
		var rem = t.closest( '.fauth-passkey-remove' );
		var sign = t.closest( '.fauth-passkey-signin' );
		if ( add ) { e.preventDefault(); register( add ); }
		else if ( rem ) { e.preventDefault(); remove( rem ); }
		else if ( sign ) { e.preventDefault(); signIn( sign ); }
	} );
}() );
