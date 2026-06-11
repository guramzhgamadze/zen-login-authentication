/**
 * Frontend Auth – Frontend Script
 *
 * Bug 10 fix: rewritten from jQuery IIFE to ES6 arrow-function IIFE.
 * jQuery is still used for $.ajax (required because jquery is a dependency)
 * but the outer structure is now ES6. ajaxUrl was previously passed via
 * fauthConfig but never used (JS posted to the form's action URL, not
 * admin-ajax.php). That is correct — forms post to their own page URL
 * so WordPress processes them via template_redirect. ajaxUrl removed from
 * the data object to avoid confusion.
 *
 * LOAD ORDER NOTE (v1.4.5 fix — previously stated strategy:'defer' incorrectly):
 * This script is registered with [ 'in_footer' => true ] and NO strategy:'defer'.
 * Defer is intentionally omitted for Elementor compatibility — Elementor's own
 * scripts are not deferred, and widget scripts must execute in document order
 * after Elementor's boot code. With in_footer:true the script tag is placed
 * at the bottom of <body>; the HTML parser has fully processed all DOM nodes
 * above the tag by that point, so direct init() calls at the bottom of this
 * IIFE are safe without any DOMContentLoaded listener.
 *
 * Source: developer.wordpress.org/reference/functions/wp_register_script/
 *         make.wordpress.org/core/2023/07/14/registering-scripts-with-async-and-defer-attributes-in-wordpress-6-3/
 */

/* global fauthConfig, jQuery */

( () => {
    'use strict';

    // -----------------------------------------------------------------------
    // AJAX form submission
    // -----------------------------------------------------------------------

    const bindForms = () => {
        if ( ! fauthConfig.useAjax ) {
            return;
        }

        document.querySelectorAll( '.fauth-inner-form[data-ajax="1"]' ).forEach( form => {
            form.addEventListener( 'submit', e => {
                e.preventDefault();
                submitForm( form );
            } );
        } );
    };

    const submitForm = ( form ) => {
        const container = form.closest( '.fauth-form' );
        const btn       = form.querySelector( '.fauth-submit-button' );
        const origText  = btn ? btn.textContent : '';

        clearNotices( container );

        if ( btn ) {
            btn.disabled  = true;
            btn.innerHTML = '<span class="fauth-spinner" aria-hidden="true"></span>' + escHtml( origText );
        }

        // BUG-I fix: FormData was created but never used — jQuery serialize() is used instead.
        // Forms post to their own action URL, processed by template_redirect.
        jQuery.ajax( {
            url:         form.getAttribute( 'action' ) || window.location.href,
            method:      'POST',
            data:        jQuery( form ).serialize() + '&fauth_ajax=1',
            dataType:    'json',
        } )
        .done( response => {
            if ( response && response.success ) {
                const payload = response.data || {};

                if ( payload.redirect ) {
                    window.location.href = payload.redirect;
                    return;
                }

                if ( payload.message ) {
                    showMessage( container, payload.message );
                }

                form.reset();
            } else {
                const errors = ( response && response.data && response.data.errors )
                    ? response.data.errors
                    : [ fauthConfig.i18n.genericError ];

                showErrors( container, errors );
            }
        } )
        .fail( () => {
            showErrors( container, [ fauthConfig.i18n.genericError ] );
        } )
        .always( () => {
            if ( btn ) {
                btn.disabled    = false;
                btn.textContent = origText;
            }
        } );
    };

    // -----------------------------------------------------------------------
    // Notice helpers
    // -----------------------------------------------------------------------

    const clearNotices = ( container ) => {
        container.querySelectorAll( '.fauth-errors, .fauth-messages' ).forEach( el => {
            el.innerHTML = '';
        } );
    };

    const getOrCreateList = ( container, cls, role ) => {
        let list = container.querySelector( '.' + cls );
        if ( ! list ) {
            list = document.createElement( 'ul' );
            list.className = cls;
            if ( role ) {
                list.setAttribute( 'role', role );
            }
            container.prepend( list );
        }
        return list;
    };

    const showErrors = ( container, messages ) => {
        const list = getOrCreateList( container, 'fauth-errors', 'alert' );
        messages.forEach( msg => {
            const li = document.createElement( 'li' );
            li.className   = 'fauth-error';
            li.textContent = msg;
            list.appendChild( li );
        } );
    };

    const showMessage = ( container, message ) => {
        const list = getOrCreateList( container, 'fauth-messages', 'status' );
        const li   = document.createElement( 'li' );
        li.className   = 'fauth-message';
        li.textContent = message;
        list.appendChild( li );
    };

    // -----------------------------------------------------------------------
    // Show / hide password toggle
    // -----------------------------------------------------------------------

    // Fix D — accepts a scope element so it can be re-run per widget instance
    const bindPasswordToggle = ( scope = document ) => {
        // Inject toggle buttons next to each password field.
        // Guard: skip inputs that already have a toggle sibling to prevent duplicates.
        scope.querySelectorAll( '.fauth-inner-form input[type="password"]' ).forEach( input => {
            if ( input.nextElementSibling && input.nextElementSibling.classList.contains( 'fauth-password-toggle' ) ) {
                return; // already processed
            }
            if ( ! input.id ) {
                return;
            }

            const btn = document.createElement( 'button' );
            btn.type           = 'button';
            btn.className      = 'fauth-password-toggle';
            btn.dataset.target = input.id;
            // Per-field values override global i18n — set by Elementor widget controls
            // via data-toggle-show / data-toggle-hide attrs rendered on the <input>.
            btn.dataset.show   = input.dataset.toggleShow || fauthConfig.i18n.show;
            btn.dataset.hide   = input.dataset.toggleHide || fauthConfig.i18n.hide;
            btn.setAttribute( 'aria-pressed', 'false' );
            // BUG-J fix: use translatable string from PHP data object.
            btn.setAttribute( 'aria-label', fauthConfig.i18n.passwordToggle );
            btn.textContent = btn.dataset.show;

            input.insertAdjacentElement( 'afterend', btn );

            // Fix J — add flex-layout modifier class to the parent field wrap
            const wrap = input.closest( '.fauth-field-wrap' );
            if ( wrap ) {
                wrap.classList.add( 'fauth-field-wrap--password' );
            }
        } );

        // FIX: Removed document.addEventListener('click', ...) from here.
        //
        // Previously, the click delegation handler was INSIDE bindPasswordToggle().
        // This function is called on initial boot AND on every Elementor element_ready
        // re-render. Each call stacked a new document-level click listener — after N
        // re-renders there were N+1 identical handlers all toggling the same password
        // field, causing a visible flicker (hide→show→hide→show in rapid succession).
        //
        // The delegation handler is now registered ONCE at boot time (see
        // initPasswordToggleDelegate below). Since it uses event delegation on
        // document, it automatically handles dynamically-injected toggle buttons
        // without needing to be re-bound.
    };

    /**
     * Single document-level click delegate for password toggle buttons.
     * Registered once at boot time — handles all current and future toggle buttons.
     */
    const initPasswordToggleDelegate = () => {
        document.addEventListener( 'click', e => {
            const btn = e.target.closest( '.fauth-password-toggle' );
            if ( ! btn ) {
                return;
            }
            const input      = document.getElementById( btn.dataset.target );
            if ( ! input ) {
                return;
            }
            const isPassword = input.type === 'password';
            input.type       = isPassword ? 'text' : 'password';
            btn.textContent  = isPassword ? btn.dataset.hide : btn.dataset.show;
            btn.setAttribute( 'aria-pressed', isPassword ? 'true' : 'false' );
        } );
    };

    // -----------------------------------------------------------------------
    // Password strength meter
    // -----------------------------------------------------------------------

    // Fix D — scope-aware version for element_ready re-binding
    const bindPasswordStrength = ( scope = document ) => {
        const pass1 = scope.querySelector( '#pass1, #user_pass1' );
        const pass2 = scope.querySelector( '#pass2, #user_pass2' );

        if ( ! pass1 ) {
            return;
        }

        let meter = document.getElementById( 'pass-strength-result' );
        if ( ! meter ) {
            meter            = document.createElement( 'div' );
            meter.id         = 'pass-strength-result';
            meter.setAttribute( 'aria-live', 'polite' );
            pass1.closest( '.fauth-field-wrap' )?.insertAdjacentElement( 'afterend', meter );
        }

        const update = () => checkStrength( pass1.value, pass2 ? pass2.value : '', meter );
        pass1.addEventListener( 'input', update );
        if ( pass2 ) {
            pass2.addEventListener( 'input', update );
        }
    };

    const checkStrength = ( pass1, pass2, meter ) => {
        if ( ! pass1 ) {
            meter.className   = '';
            meter.textContent = '';
            meter.style.opacity = '0';
            return;
        }

        let strength = 0;

        // Use WordPress's built-in strength meter if available.
        if ( window.wp && wp.passwordStrength ) {
            strength = wp.passwordStrength.meter(
                pass1,
                wp.passwordStrength.userInputDisallowedList(),
                pass2
            );
        } else {
            // Simple fallback heuristic.
            if ( pass1.length >= 8 )                                    strength++;
            if ( pass1.length >= 12 )                                   strength++;
            if ( /[A-Z]/.test( pass1 ) && /[a-z]/.test( pass1 ) )      strength++;
            if ( /[0-9]/.test( pass1 ) )                                strength++;
            if ( /[^A-Za-z0-9]/.test( pass1 ) )                        strength++;
            if ( pass2 && pass1 !== pass2 )                             strength = Math.max( 0, strength - 2 );
            strength = Math.min( 4, Math.max( 1, Math.ceil( strength / 1.25 ) ) );
        }

        // BUG-6 fix: labels come from PHP i18n data — fully translatable.
        const labels  = [
            '',
            fauthConfig.i18n.strengthVeryWeak,
            fauthConfig.i18n.strengthWeak,
            fauthConfig.i18n.strengthGood,
            fauthConfig.i18n.strengthStrong,
        ];
        const classes = [ '', 'short', 'bad', 'good', 'strong' ];

        meter.className     = classes[ strength ] || 'short';
        meter.textContent   = labels[ strength ] || '';
        meter.style.opacity = '1';
    };

    // -----------------------------------------------------------------------
    // Handle query-string success/info messages on page load
    // -----------------------------------------------------------------------

    const handleQueryMessages = () => {
        const container = document.querySelector( '.fauth-form' );
        if ( ! container ) {
            return;
        }

        const params = new URLSearchParams( window.location.search );

        // BUG-7 fix: messages now come from PHP i18n data — fully translatable.
        if ( params.get( 'password' ) === 'changed' ) {
            showMessage( container, fauthConfig.i18n.msgPasswordChanged );
        }

        if ( params.has( 'registered' ) ) {
            showMessage( container, fauthConfig.i18n.msgRegistered );
        }

        if ( params.has( 'checkemail' ) ) {
            showMessage( container, fauthConfig.i18n.msgCheckEmail );
        }
    };

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    const escHtml = ( str ) => {
        const d  = document.createElement( 'div' );
        d.textContent = str;
        return d.innerHTML;
    };

    // -----------------------------------------------------------------------
    // Boot — safe to call directly because in_footer:true places this script
    // tag after all DOM content in <body>, so all elements above are already
    // parsed and accessible at execution time. No DOMContentLoaded needed.
    // -----------------------------------------------------------------------

    // Guard: bail out if the PHP-generated config object is missing.
    // This can happen if wp_add_inline_script() failed or the script loaded
    // on a page without the inline config block.
    if ( typeof fauthConfig === 'undefined' ) {
        return;
    }

    bindForms();
    bindPasswordStrength();
    handleQueryMessages();

    // Register the document-level click delegate for password toggle — ONCE.
    initPasswordToggleDelegate();

    // Fix D — direct call for non-Elementor pages (classic WP pages, shortcodes, sidebar widgets)
    bindPasswordToggle( document );

    // Fix D — also bind via Elementor element_ready so toggles survive editor re-renders
    // and AJAX-loaded pages (Theme Builder popups, loop items, etc.)
    //
    // FIX: Changed from window.addEventListener('elementor/frontend/init', ...) to
    // jQuery(window).on('elementor/frontend/init', ...).
    //
    // Elementor fires this event via jQuery's event system:
    //   jQuery(window).trigger('elementor/frontend/init')
    // Native addEventListener() cannot catch jQuery-triggered custom events —
    // the element_ready hooks were never registered, so password toggles and
    // strength meters failed on Elementor AJAX-loaded content (Theme Builder
    // popups, loop items, editor preview re-renders).
    //
    // jQuery is guaranteed available because it's a declared script dependency.
    //
    // Source: github.com/elementor/elementor/blob/main/assets/dev/js/frontend/frontend.js
    //         (elementorFrontend.trigger('elementor/frontend/init'))
    if ( typeof jQuery !== 'undefined' ) {
        jQuery( window ).on( 'elementor/frontend/init', () => {
            const widgetNames = [ 'fauth-login', 'fauth-register', 'fauth-reset-password' ];
            widgetNames.forEach( name => {
                window.elementorFrontend.hooks.addAction(
                    `frontend/element_ready/${ name }.default`,
                    ( $scope ) => {
                        if ( ! $scope || ! $scope[ 0 ] ) { return; }
                        bindPasswordToggle( $scope[ 0 ] );
                        bindPasswordStrength( $scope[ 0 ] );
                    }
                );
            } );
        } );
    }

} )();
