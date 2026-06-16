/**
 * Zen Login & Authentication – 2FA front-end helpers.
 *
 *  1. Draws the enrollment QR locally (no network) from the otpauth:// URI in
 *     .fauth-2fa-qr[data-otpauth], using the bundled qrcode-generator library.
 *     If the library isn't present, the manual setup key is the fallback.
 *  2. Wires the one-time recovery-code "Copy" and "Download" buttons, reading
 *     the codes straight from the rendered list (nothing is stored or re-fetched).
 */
( function () {
	'use strict';

	function renderQrCodes() {
		if ( typeof window.qrcode !== 'function' ) {
			return;
		}
		var nodes = document.querySelectorAll( '.fauth-2fa-qr[data-otpauth]' );
		for ( var i = 0; i < nodes.length; i++ ) {
			var el = nodes[ i ];
			if ( '1' === el.getAttribute( 'data-rendered' ) ) {
				continue;
			}
			var data = el.getAttribute( 'data-otpauth' );
			if ( ! data ) {
				continue;
			}
			try {
				var qr = window.qrcode( 0, 'M' ); // type 0 = auto-size, error level M
				qr.addData( data );
				qr.make();
				el.innerHTML = qr.createSvgTag( { cellSize: 4, margin: 8, scalable: true } );
				el.setAttribute( 'data-rendered', '1' );
				el.removeAttribute( 'aria-hidden' );
			} catch ( e ) {
				/* Leave the manual key visible as the fallback. */
			}
		}
	}

	function collectCodes( box ) {
		var codes = [];
		var nodes = box.querySelectorAll( '.fauth-2fa-code-list code' );
		for ( var i = 0; i < nodes.length; i++ ) {
			var v = ( nodes[ i ].textContent || '' ).trim();
			if ( v ) {
				codes.push( v );
			}
		}
		return codes;
	}

	function fallbackCopy( text ) {
		var ta = document.createElement( 'textarea' );
		ta.value = text;
		ta.setAttribute( 'readonly', '' );
		ta.style.position = 'absolute';
		ta.style.left = '-9999px';
		document.body.appendChild( ta );
		ta.select();
		try { document.execCommand( 'copy' ); } catch ( e ) {}
		document.body.removeChild( ta );
	}

	function setupCodeActions() {
		var sections = document.querySelectorAll( '.fauth-2fa' );
		for ( var s = 0; s < sections.length; s++ ) {
			( function ( section ) {
				if ( '1' === section.getAttribute( 'data-codes-bound' ) ) {
					return;
				}
				// The Copy/Download buttons live OUTSIDE the .fauth-2fa-codes box
				// (siblings within .fauth-2fa), so scope the lookup to the section.
				var copyBtn = section.querySelector( '.fauth-2fa-copy' );
				var dlBtn   = section.querySelector( '.fauth-2fa-download' );
				if ( ! copyBtn && ! dlBtn ) {
					return;
				}
				var codes = collectCodes( section );
				if ( ! codes.length ) {
					return;
				}
				section.setAttribute( 'data-codes-bound', '1' );
				var text = codes.join( '\n' ) + '\n';

				if ( copyBtn ) {
					copyBtn.addEventListener( 'click', function () {
						var flash = function () {
							var orig = copyBtn.textContent;
							var done = copyBtn.getAttribute( 'data-done' );
							if ( done ) {
								copyBtn.textContent = done;
								setTimeout( function () { copyBtn.textContent = orig; }, 2000 );
							}
						};
						if ( navigator.clipboard && navigator.clipboard.writeText ) {
							navigator.clipboard.writeText( text ).then( flash, function () { fallbackCopy( text ); flash(); } );
						} else {
							fallbackCopy( text );
							flash();
						}
					} );
				}

				if ( dlBtn ) {
					dlBtn.addEventListener( 'click', function () {
						var heading = dlBtn.getAttribute( 'data-heading' );
						var body    = ( heading ? heading + '\n\n' : '' ) + text;
						var blob    = new Blob( [ body ], { type: 'text/plain;charset=utf-8' } );
						var url     = URL.createObjectURL( blob );
						var a       = document.createElement( 'a' );
						a.href      = url;
						a.download  = dlBtn.getAttribute( 'data-filename' ) || 'recovery-codes.txt';
						document.body.appendChild( a );
						a.click();
						document.body.removeChild( a );
						setTimeout( function () { URL.revokeObjectURL( url ); }, 1000 );
					} );
				}
			} )( sections[ s ] );
		}
	}

	function init() {
		renderQrCodes();
		setupCodeActions();
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
} )();
