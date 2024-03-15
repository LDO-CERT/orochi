(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.mar10 = {}));
})(this, (function (exports) { 'use strict';

    /*!
     * debounce & throttle, taken from https://github.com/lodash/lodash v4.17.21
     * MIT License: https://raw.githubusercontent.com/lodash/lodash/4.17.21-npm/LICENSE
     * Modified for TypeScript type annotations.
     */
    /* --- */
    /** Detect free variable `global` from Node.js. */
    const freeGlobal = typeof global === "object" &&
        global !== null &&
        global.Object === Object &&
        global;
    /** Detect free variable `globalThis` */
    const freeGlobalThis = typeof globalThis === "object" &&
        globalThis !== null &&
        globalThis.Object == Object &&
        globalThis;
    /** Detect free variable `self`. */
    const freeSelf = typeof self === "object" && self !== null && self.Object === Object && self;
    /** Used as a reference to the global object. */
    const root = freeGlobalThis || freeGlobal || freeSelf || Function("return this")();
    /**
     * Checks if `value` is the
     * [language type](http://www.ecma-international.org/ecma-262/7.0/#sec-ecmascript-language-types)
     * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
     *
     * @since 0.1.0
     * @category Lang
     * @param {*} value The value to check.
     * @returns {boolean} Returns `true` if `value` is an object, else `false`.
     * @example
     *
     * isObject({})
     * // => true
     *
     * isObject([1, 2, 3])
     * // => true
     *
     * isObject(Function)
     * // => true
     *
     * isObject(null)
     * // => false
     */
    function isObject(value) {
        const type = typeof value;
        return value != null && (type === "object" || type === "function");
    }
    /**
     * Creates a debounced function that delays invoking `func` until after `wait`
     * milliseconds have elapsed since the last time the debounced function was
     * invoked, or until the next browser frame is drawn. The debounced function
     * comes with a `cancel` method to cancel delayed `func` invocations and a
     * `flush` method to immediately invoke them. Provide `options` to indicate
     * whether `func` should be invoked on the leading and/or trailing edge of the
     * `wait` timeout. The `func` is invoked with the last arguments provided to the
     * debounced function. Subsequent calls to the debounced function return the
     * result of the last `func` invocation.
     *
     * **Note:** If `leading` and `trailing` options are `true`, `func` is
     * invoked on the trailing edge of the timeout only if the debounced function
     * is invoked more than once during the `wait` timeout.
     *
     * If `wait` is `0` and `leading` is `false`, `func` invocation is deferred
     * until the next tick, similar to `setTimeout` with a timeout of `0`.
     *
     * If `wait` is omitted in an environment with `requestAnimationFrame`, `func`
     * invocation will be deferred until the next frame is drawn (typically about
     * 16ms).
     *
     * See [David Corbacho's article](https://css-tricks.com/debouncing-throttling-explained-examples/)
     * for details over the differences between `debounce` and `throttle`.
     *
     * @since 0.1.0
     * @category Function
     * @param {Function} func The function to debounce.
     * @param {number} [wait=0]
     *  The number of milliseconds to delay; if omitted, `requestAnimationFrame` is
     *  used (if available).
     * @param {Object} [options={}] The options object.
     * @param {boolean} [options.leading=false]
     *  Specify invoking on the leading edge of the timeout.
     * @param {number} [options.maxWait]
     *  The maximum time `func` is allowed to be delayed before it's invoked.
     * @param {boolean} [options.trailing=true]
     *  Specify invoking on the trailing edge of the timeout.
     * @returns {Function} Returns the new debounced function.
     * @example
     *
     * // Avoid costly calculations while the window size is in flux.
     * jQuery(window).on('resize', debounce(calculateLayout, 150))
     *
     * // Invoke `sendMail` when clicked, debouncing subsequent calls.
     * jQuery(element).on('click', debounce(sendMail, 300, {
     *   'leading': true,
     *   'trailing': false
     * }))
     *
     * // Ensure `batchLog` is invoked once after 1 second of debounced calls.
     * const debounced = debounce(batchLog, 250, { 'maxWait': 1000 })
     * const source = new EventSource('/stream')
     * jQuery(source).on('message', debounced)
     *
     * // Cancel the trailing debounced invocation.
     * jQuery(window).on('popstate', debounced.cancel)
     *
     * // Check for pending invocations.
     * const status = debounced.pending() ? "Pending..." : "Ready"
     */
    function debounce(func, wait = 0, options = {}) {
        let lastArgs, lastThis, maxWait, result, timerId, lastCallTime;
        let lastInvokeTime = 0;
        let leading = false;
        let maxing = false;
        let trailing = true;
        // Bypass `requestAnimationFrame` by explicitly setting `wait=0`.
        const useRAF = !wait && wait !== 0 && typeof root.requestAnimationFrame === "function";
        if (typeof func !== "function") {
            throw new TypeError("Expected a function");
        }
        wait = +wait || 0;
        if (isObject(options)) {
            leading = !!options.leading;
            maxing = "maxWait" in options;
            maxWait = maxing ? Math.max(+options.maxWait || 0, wait) : maxWait;
            trailing = "trailing" in options ? !!options.trailing : trailing;
        }
        function invokeFunc(time) {
            const args = lastArgs;
            const thisArg = lastThis;
            lastArgs = lastThis = undefined;
            lastInvokeTime = time;
            result = func.apply(thisArg, args);
            return result;
        }
        function startTimer(pendingFunc, wait) {
            if (useRAF) {
                root.cancelAnimationFrame(timerId);
                return root.requestAnimationFrame(pendingFunc);
            }
            return setTimeout(pendingFunc, wait);
        }
        function cancelTimer(id) {
            if (useRAF) {
                return root.cancelAnimationFrame(id);
            }
            clearTimeout(id);
        }
        function leadingEdge(time) {
            // Reset any `maxWait` timer.
            lastInvokeTime = time;
            // Start the timer for the trailing edge.
            timerId = startTimer(timerExpired, wait);
            // Invoke the leading edge.
            return leading ? invokeFunc(time) : result;
        }
        function remainingWait(time) {
            const timeSinceLastCall = time - lastCallTime;
            const timeSinceLastInvoke = time - lastInvokeTime;
            const timeWaiting = wait - timeSinceLastCall;
            return maxing
                ? Math.min(timeWaiting, maxWait - timeSinceLastInvoke)
                : timeWaiting;
        }
        function shouldInvoke(time) {
            const timeSinceLastCall = time - lastCallTime;
            const timeSinceLastInvoke = time - lastInvokeTime;
            // Either this is the first call, activity has stopped and we're at the
            // trailing edge, the system time has gone backwards and we're treating
            // it as the trailing edge, or we've hit the `maxWait` limit.
            return (lastCallTime === undefined ||
                timeSinceLastCall >= wait ||
                timeSinceLastCall < 0 ||
                (maxing && timeSinceLastInvoke >= maxWait));
        }
        function timerExpired() {
            const time = Date.now();
            if (shouldInvoke(time)) {
                return trailingEdge(time);
            }
            // Restart the timer.
            timerId = startTimer(timerExpired, remainingWait(time));
        }
        function trailingEdge(time) {
            timerId = undefined;
            // Only invoke if we have `lastArgs` which means `func` has been
            // debounced at least once.
            if (trailing && lastArgs) {
                return invokeFunc(time);
            }
            lastArgs = lastThis = undefined;
            return result;
        }
        function cancel() {
            if (timerId !== undefined) {
                cancelTimer(timerId);
            }
            lastInvokeTime = 0;
            lastArgs = lastCallTime = lastThis = timerId = undefined;
        }
        function flush() {
            return timerId === undefined ? result : trailingEdge(Date.now());
        }
        function pending() {
            return timerId !== undefined;
        }
        function debounced(...args) {
            const time = Date.now();
            const isInvoking = shouldInvoke(time);
            lastArgs = args;
            // eslint-disable-next-line  @typescript-eslint/no-this-alias
            lastThis = this;
            lastCallTime = time;
            if (isInvoking) {
                if (timerId === undefined) {
                    return leadingEdge(lastCallTime);
                }
                if (maxing) {
                    // Handle invocations in a tight loop.
                    timerId = startTimer(timerExpired, wait);
                    return invokeFunc(lastCallTime);
                }
            }
            if (timerId === undefined) {
                timerId = startTimer(timerExpired, wait);
            }
            return result;
        }
        debounced.cancel = cancel;
        debounced.flush = flush;
        debounced.pending = pending;
        return debounced;
    }
    /**
     * Creates a throttled function that only invokes `func` at most once per
     * every `wait` milliseconds (or once per browser frame). The throttled function
     * comes with a `cancel` method to cancel delayed `func` invocations and a
     * `flush` method to immediately invoke them. Provide `options` to indicate
     * whether `func` should be invoked on the leading and/or trailing edge of the
     * `wait` timeout. The `func` is invoked with the last arguments provided to the
     * throttled function. Subsequent calls to the throttled function return the
     * result of the last `func` invocation.
     *
     * **Note:** If `leading` and `trailing` options are `true`, `func` is
     * invoked on the trailing edge of the timeout only if the throttled function
     * is invoked more than once during the `wait` timeout.
     *
     * If `wait` is `0` and `leading` is `false`, `func` invocation is deferred
     * until the next tick, similar to `setTimeout` with a timeout of `0`.
     *
     * If `wait` is omitted in an environment with `requestAnimationFrame`, `func`
     * invocation will be deferred until the next frame is drawn (typically about
     * 16ms).
     *
     * See [David Corbacho's article](https://css-tricks.com/debouncing-throttling-explained-examples/)
     * for details over the differences between `throttle` and `debounce`.
     *
     * @since 0.1.0
     * @category Function
     * @param {Function} func The function to throttle.
     * @param {number} [wait=0]
     *  The number of milliseconds to throttle invocations to; if omitted,
     *  `requestAnimationFrame` is used (if available).
     * @param {Object} [options={}] The options object.
     * @param {boolean} [options.leading=true]
     *  Specify invoking on the leading edge of the timeout.
     * @param {boolean} [options.trailing=true]
     *  Specify invoking on the trailing edge of the timeout.
     * @returns {Function} Returns the new throttled function.
     * @example
     *
     * // Avoid excessively updating the position while scrolling.
     * jQuery(window).on('scroll', throttle(updatePosition, 100))
     *
     * // Invoke `renewToken` when the click event is fired, but not more than once every 5 minutes.
     * const throttled = throttle(renewToken, 300000, { 'trailing': false })
     * jQuery(element).on('click', throttled)
     *
     * // Cancel the trailing throttled invocation.
     * jQuery(window).on('popstate', throttled.cancel)
     */
    function throttle(func, wait = 0, options = {}) {
        let leading = true;
        let trailing = true;
        if (typeof func !== "function") {
            throw new TypeError("Expected a function");
        }
        if (isObject(options)) {
            leading = "leading" in options ? !!options.leading : leading;
            trailing = "trailing" in options ? !!options.trailing : trailing;
        }
        return debounce(func, wait, {
            leading,
            trailing,
            maxWait: wait,
        });
    }

    /*!
     * Wunderbaum - util
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    /** @module util */
    /** Readable names for `MouseEvent.button` */
    const MOUSE_BUTTONS = {
        0: "",
        1: "left",
        2: "middle",
        3: "right",
        4: "back",
        5: "forward",
    };
    const MAX_INT = 9007199254740991;
    const userInfo = _getUserInfo();
    /**True if the client is using a macOS platform. */
    const isMac = userInfo.isMac;
    const REX_HTML = /[&<>"'/]/g; // Escape those characters
    const REX_TOOLTIP = /[<>"'/]/g; // Don't escape `&` in tooltips
    const ENTITY_MAP = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "/": "&#x2F;",
    };
    /** A generic error that can be thrown to indicate a validation error when
     * handling the `apply` event for a node title or the `change` event for a
     * grid cell.
     */
    class ValidationError extends Error {
        constructor(message) {
            super(message);
            this.name = "ValidationError";
        }
    }
    /**
     * A ES6 Promise, that exposes the resolve()/reject() methods.
     *
     * TODO: See [Promise.withResolvers()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/withResolvers#description)
     * , a proposed standard, but not yet implemented in any browser.
     */
    let Deferred$1 = class Deferred {
        constructor() {
            this.thens = [];
            this.catches = [];
            this.status = "";
        }
        resolve(value) {
            if (this.status) {
                throw new Error("already settled");
            }
            this.status = "resolved";
            this.resolvedValue = value;
            this.thens.forEach((t) => t(value));
            this.thens = []; // Avoid memleaks.
        }
        reject(error) {
            if (this.status) {
                throw new Error("already settled");
            }
            this.status = "rejected";
            this.rejectedError = error;
            this.catches.forEach((c) => c(error));
            this.catches = []; // Avoid memleaks.
        }
        then(cb) {
            if (status === "resolved") {
                cb(this.resolvedValue);
            }
            else {
                this.thens.unshift(cb);
            }
        }
        catch(cb) {
            if (this.status === "rejected") {
                cb(this.rejectedError);
            }
            else {
                this.catches.unshift(cb);
            }
        }
        promise() {
            return {
                then: this.then,
                catch: this.catch,
            };
        }
    };
    /**Throw an `Error` if `cond` is falsey. */
    function assert(cond, msg) {
        if (!cond) {
            msg = msg || "Assertion failed.";
            throw new Error(msg);
        }
    }
    function _getUserInfo() {
        const nav = navigator;
        // const ua = nav.userAgentData;
        const res = {
            isMac: /Mac/.test(nav.platform),
        };
        return res;
    }
    /** Run `callback` when document was loaded. */
    function documentReady(callback) {
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", callback);
        }
        else {
            callback();
        }
    }
    /** Resolve when document was loaded. */
    function documentReadyPromise() {
        return new Promise((resolve) => {
            documentReady(resolve);
        });
    }
    /**
     * Iterate over Object properties or array elements.
     *
     * @param obj `Object`, `Array` or null
     * @param callback(index, item) called for every item.
     *  `this` also contains the item.
     *  Return `false` to stop the iteration.
     */
    function each(obj, callback) {
        if (obj == null) {
            // accept `null` or `undefined`
            return obj;
        }
        const length = obj.length;
        let i = 0;
        if (typeof length === "number") {
            for (; i < length; i++) {
                if (callback.call(obj[i], i, obj[i]) === false) {
                    break;
                }
            }
        }
        else {
            for (const k in obj) {
                if (callback.call(obj[i], k, obj[k]) === false) {
                    break;
                }
            }
        }
        return obj;
    }
    /** Shortcut for `throw new Error(msg)`.*/
    function error(msg) {
        throw new Error(msg);
    }
    /** Convert `<`, `>`, `&`, `"`, `'`, and `/` to the equivalent entities. */
    function escapeHtml(s) {
        return ("" + s).replace(REX_HTML, function (s) {
            return ENTITY_MAP[s];
        });
    }
    // export function escapeRegExp(s: string) {
    //   return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); // $& means the whole matched string
    // }
    /**Convert a regular expression string by escaping special characters (e.g. `"$"` -> `"\$"`) */
    function escapeRegex(s) {
        return ("" + s).replace(/([.?*+^$[\]\\(){}|-])/g, "\\$1");
    }
    /** Convert `<`, `>`, `"`, `'`, and `/` (but not `&`) to the equivalent entities. */
    function escapeTooltip(s) {
        return ("" + s).replace(REX_TOOLTIP, function (s) {
            return ENTITY_MAP[s];
        });
    }
    /** TODO */
    function extractHtmlText(s) {
        if (s.indexOf(">") >= 0) {
            error("Not implemented");
            // return $("<div/>").html(s).text();
        }
        return s;
    }
    /**
     * Read the value from an HTML input element.
     *
     * If a `<span class="wb-col">` is passed, the first child input is used.
     * Depending on the target element type, `value` is interpreted accordingly.
     * For example for a checkbox, a value of true, false, or null is returned if
     * the element is checked, unchecked, or indeterminate.
     * For datetime input control a numerical value is assumed, etc.
     *
     * Common use case: store the new user input in a `change` event handler:
     *
     * ```ts
     *   change: (e) => {
     *     const tree = e.tree;
     *     const node = e.node;
     *     // Read the value from the input control that triggered the change event:
     *     let value = tree.getValueFromElem(e.element);
     *     // and store it to the node model (assuming the column id matches the property name)
     *     node.data[e.info.colId] = value;
     *   },
     * ```
     * @param elem `<input>` or `<select>` element. Also a parent `span.wb-col` is accepted.
     * @param coerce pass true to convert date/time inputs to `Date`.
     * @returns the value
     */
    function getValueFromElem(elem, coerce = false) {
        const tag = elem.tagName;
        let value = null;
        if (tag === "SPAN" && elem.classList.contains("wb-col")) {
            const span = elem;
            const embeddedInput = span.querySelector("input,select");
            if (embeddedInput) {
                return getValueFromElem(embeddedInput, coerce);
            }
            span.innerText = "" + value;
        }
        else if (tag === "INPUT") {
            const input = elem;
            const type = input.type;
            switch (type) {
                case "button":
                case "reset":
                case "submit":
                case "image":
                    break;
                case "checkbox":
                    value = input.indeterminate ? null : input.checked;
                    break;
                case "date":
                case "datetime":
                case "datetime-local":
                case "month":
                case "time":
                case "week":
                    value = coerce ? input.valueAsDate : input.value;
                    break;
                case "number":
                case "range":
                    value = input.valueAsNumber;
                    break;
                case "radio":
                    {
                        const name = input.name;
                        const checked = input.parentElement.querySelector(`input[name="${name}"]:checked`);
                        value = checked ? checked.value : undefined;
                    }
                    break;
                case "text":
                default:
                    value = input.value;
            }
        }
        else if (tag === "SELECT") {
            const select = elem;
            value = select.value;
        }
        return value;
    }
    /**
     * Set the value of an HTML input element.
     *
     * If a `<span class="wb-col">` is passed, the first child input is used.
     * Depending on the target element type, `value` is interpreted accordingly.
     * For example a checkbox is set to checked, unchecked, or indeterminate if the
     * value is truethy, falsy, or `null`.
     * For datetime input control a numerical value is assumed, etc.
     *
     * Common use case: update embedded input controls in a `render` event handler:
     *
     * ```ts
     *   render: (e) => {
     *     // e.node.log(e.type, e, e.node.data);
     *
     *     for (const col of Object.values(e.renderColInfosById)) {
     *       switch (col.id) {
     *         default:
     *           // Assumption: we named column.id === node.data.NAME
     *           util.setValueToElem(col.elem, e.node.data[col.id]);
     *           break;
     *       }
     *     }
     *   },
     * ```
     *
     * @param elem `<input>` or `<select>` element Also a parent `span.wb-col` is accepted.
     * @param value a value that matches the target element.
     */
    function setValueToElem(elem, value) {
        const tag = elem.tagName;
        if (tag === "SPAN" && elem.classList.contains("wb-col")) {
            const span = elem;
            const embeddedInput = span.querySelector("input,select");
            if (embeddedInput) {
                return setValueToElem(embeddedInput, value);
            }
            // No embedded input: simply write as escaped html
            span.innerText = "" + value;
        }
        else if (tag === "INPUT") {
            const input = elem;
            const type = input.type;
            switch (type) {
                case "checkbox":
                    // An explicit `null` value is interpreted as 'indeterminate'.
                    // `undefined` is interpreted as 'unchecked'
                    input.indeterminate = value === null;
                    input.checked = !!value;
                    break;
                case "date":
                case "month":
                case "time":
                case "week":
                case "datetime":
                case "datetime-local":
                    input.valueAsDate = new Date(value);
                    break;
                case "number":
                case "range":
                    if (value == null) {
                        input.value = value;
                    }
                    else {
                        input.valueAsNumber = value;
                    }
                    break;
                case "radio":
                    error(`Not yet implemented: ${type}`);
                    // const name = input.name;
                    // const checked = input.parentElement!.querySelector(
                    //   `input[name="${name}"]:checked`
                    // );
                    // value = checked ? (<HTMLInputElement>checked).value : undefined;
                    break;
                case "button":
                case "reset":
                case "submit":
                case "image":
                    break;
                case "text":
                default:
                    input.value = value !== null && value !== void 0 ? value : "";
            }
        }
        else if (tag === "SELECT") {
            const select = elem;
            if (value == null) {
                select.selectedIndex = -1;
            }
            else {
                select.value = value;
            }
        }
    }
    /** Show/hide element by setting the `display` style to 'none'. */
    function setElemDisplay(elem, flag) {
        const style = elemFromSelector(elem).style;
        if (flag) {
            if (style.display === "none") {
                style.display = "";
            }
        }
        else if (style.display === "") {
            style.display = "none";
        }
    }
    /** Create and return an unconnected `HTMLElement` from a HTML string. */
    function elemFromHtml(html) {
        const t = document.createElement("template");
        t.innerHTML = html.trim();
        return t.content.firstElementChild;
    }
    const _IGNORE_KEYS = new Set(["Alt", "Control", "Meta", "Shift"]);
    /** Return a HtmlElement from selector or cast an existing element. */
    function elemFromSelector(obj) {
        if (!obj) {
            return null; //(null as unknown) as HTMLElement;
        }
        if (typeof obj === "string") {
            return document.querySelector(obj);
        }
        return obj;
    }
    // /** Return a EventTarget from selector or cast an existing element. */
    // export function eventTargetFromSelector(
    //   obj: string | EventTarget
    // ): EventTarget | null {
    //   if (!obj) {
    //     return null;
    //   }
    //   if (typeof obj === "string") {
    //     return document.querySelector(obj) as EventTarget;
    //   }
    //   return obj as EventTarget;
    // }
    /**
     * Return a canonical descriptive string for a keyboard or mouse event.
     *
     * The result also contains a prefix for modifiers if any, for example
     * `"x"`, `"F2"`, `"Control+Home"`, or `"Shift+clickright"`.
     * This is especially useful in `switch` statements, to make sure that modifier
     * keys are considered and handled correctly:
     * ```ts
     *   const eventName = util.eventToString(e);
     *   switch (eventName) {
     *     case "+":
     *     case "Add":
     *       ...
     *       break;
     *     case "Enter":
     *     case "End":
     *     case "Control+End":
     *     case "Meta+ArrowDown":
     *     case "PageDown":
     *       ...
     *       break;
     *   }
     * ```
     */
    function eventToString(event) {
        const key = event.key;
        const et = event.type;
        const s = [];
        if (event.altKey) {
            s.push("Alt");
        }
        if (event.ctrlKey) {
            s.push("Control");
        }
        if (event.metaKey) {
            s.push("Meta");
        }
        if (event.shiftKey) {
            s.push("Shift");
        }
        if (et === "click" || et === "dblclick") {
            s.push(MOUSE_BUTTONS[event.button] + et);
        }
        else if (et === "wheel") {
            s.push(et);
            // } else if (!IGNORE_KEYCODES[key]) {
            //   s.push(
            //     SPECIAL_KEYCODES[key] ||
            //     String.fromCharCode(key).toLowerCase()
            //   );
        }
        else if (!_IGNORE_KEYS.has(key)) {
            s.push(key);
        }
        return s.join("+");
    }
    /**
     * Copy allproperties from one or more source objects to a target object.
     *
     * @returns the modified target object.
     */
    // TODO: use Object.assign()? --> https://stackoverflow.com/a/42740894
    // TODO: support deep merge --> https://stackoverflow.com/a/42740894
    function extend(...args) {
        for (let i = 1; i < args.length; i++) {
            const arg = args[i];
            if (arg == null) {
                continue;
            }
            for (const key in arg) {
                if (Object.prototype.hasOwnProperty.call(arg, key)) {
                    args[0][key] = arg[key];
                }
            }
        }
        return args[0];
    }
    /** Return true if `obj` is of type `array`. */
    function isArray(obj) {
        return Array.isArray(obj);
    }
    /** Return true if `obj` is of type `Object` and has no propertied. */
    function isEmptyObject(obj) {
        return Object.keys(obj).length === 0 && obj.constructor === Object;
    }
    /** Return true if `obj` is of type `function`. */
    function isFunction(obj) {
        return typeof obj === "function";
    }
    /** Return true if `obj` is of type `Object`. */
    function isPlainObject(obj) {
        return Object.prototype.toString.call(obj) === "[object Object]";
    }
    /** A dummy function that does nothing ('no operation'). */
    function noop(...args) { }
    function onEvent(rootTarget, eventNames, selectorOrHandler, handlerOrNone) {
        let selector, handler;
        rootTarget = elemFromSelector(rootTarget);
        // rootTarget = eventTargetFromSelector<EventTarget>(rootTarget)!;
        if (handlerOrNone) {
            selector = selectorOrHandler;
            handler = handlerOrNone;
        }
        else {
            selector = "";
            handler = selectorOrHandler;
        }
        eventNames.split(" ").forEach((evn) => {
            rootTarget.addEventListener(evn, function (e) {
                if (!selector) {
                    return handler(e); // no event delegation
                }
                else if (e.target) {
                    let elem = e.target;
                    if (elem.matches(selector)) {
                        return handler(e);
                    }
                    elem = elem.closest(selector);
                    if (elem) {
                        return handler(e);
                    }
                }
            });
        });
    }
    /** Return a wrapped handler method, that provides `this._super` and `this._superApply`.
     *
     * ```ts
      // Implement `opts.createNode` event to add the 'draggable' attribute
      overrideMethod(ctx.options, "createNode", (event, data) => {
        // Default processing if any
        this._super.apply(this, event, data);
        // Add 'draggable' attribute
        data.node.span.draggable = true;
      });
      ```
      */
    function overrideMethod(instance, methodName, handler, ctx) {
        let prevSuper, prevSuperApply;
        const self = ctx || instance;
        const prevFunc = instance[methodName];
        const _super = (...args) => {
            return prevFunc.apply(self, args);
        };
        const _superApply = (argsArray) => {
            return prevFunc.apply(self, argsArray);
        };
        const wrapper = (...args) => {
            try {
                prevSuper = self._super;
                prevSuperApply = self._superApply;
                self._super = _super;
                self._superApply = _superApply;
                return handler.apply(self, args);
            }
            finally {
                self._super = prevSuper;
                self._superApply = prevSuperApply;
            }
        };
        instance[methodName] = wrapper;
    }
    /** Run function after ms milliseconds and return a promise that resolves when done. */
    function setTimeoutPromise(callback, ms) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                try {
                    resolve(callback.apply(this));
                }
                catch (err) {
                    reject(err);
                }
            }, ms);
        });
    }
    /**
     * Wait `ms` microseconds.
     *
     * Example:
     * ```js
     * await sleep(1000);
     * ```
     * @param ms duration
     * @returns
     */
    async function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
    /**
     * Set or rotate checkbox status with support for tri-state.
     *
     * An initial 'indeterminate' state becomes 'checked' on the first call.
     *
     * If the input element has the class 'wb-tristate' assigned, the sequence is:<br>
     * 'indeterminate' -> 'checked' -> 'unchecked' -> 'indeterminate' -> ...<br>
     * Otherwise we toggle like <br>
     * 'checked' -> 'unchecked' -> 'checked' -> ...
     */
    function toggleCheckbox(element, value, tristate) {
        const input = elemFromSelector(element);
        assert(input.type === "checkbox", `Expected a checkbox: ${input.type}`);
        tristate !== null && tristate !== void 0 ? tristate : (tristate = input.classList.contains("wb-tristate") || input.indeterminate);
        if (value === undefined) {
            const curValue = input.indeterminate ? null : input.checked;
            switch (curValue) {
                case true:
                    value = false;
                    break;
                case false:
                    value = tristate ? null : true;
                    break;
                case null:
                    value = true;
                    break;
            }
        }
        input.indeterminate = value == null;
        input.checked = !!value;
    }
    /**
     * Return `opts.NAME` if opts is valid and
     *
     * @param opts dict, object, or null
     * @param name option name (use dot notation to access extension option, e.g. `filter.mode`)
     * @param defaultValue returned when `opts` is not an object, or does not have a NAME property
     */
    function getOption(opts, name, defaultValue = undefined) {
        let ext;
        // Lookup `name` in options dict
        if (opts && name.indexOf(".") >= 0) {
            [ext, name] = name.split(".");
            opts = opts[ext];
        }
        const value = opts ? opts[name] : null;
        // Use value from value options dict, fallback do default
        return value !== null && value !== void 0 ? value : defaultValue;
    }
    /** Convert an Array or space-separated string to a Set. */
    function toSet(val) {
        if (val instanceof Set) {
            return val;
        }
        if (typeof val === "string") {
            const set = new Set();
            for (const c of val.split(" ")) {
                set.add(c.trim());
            }
            return set;
        }
        if (Array.isArray(val)) {
            return new Set(val);
        }
        throw new Error("Cannot convert to Set<string>: " + val);
    }
    // /** Check if a string is contained in an Array or Set. */
    // export function isAnyOf(s: string, items: Array<string>|Set<string>): boolean {
    //   return Array.prototype.includes.call(items, s)
    // }
    // /** Check if an Array or Set has at least one matching entry. */
    // export function hasAnyOf(container: Array<string>|Set<string>, items: Array<string>): boolean {
    //   if (Array.isArray(container)) {
    //     return container.some(v => )
    //   }
    //   return container.some(v => {})
    //   // const container = toSet(items);
    //   // const itemSet = toSet(items);
    //   // Array.prototype.includes
    //   // throw new Error("Cannot convert to Set<string>: " + val);
    // }
    /** Return a canonical string representation for an object's type (e.g. 'array', 'number', ...). */
    function type(obj) {
        return Object.prototype.toString
            .call(obj)
            .replace(/^\[object (.+)\]$/, "$1")
            .toLowerCase();
    }
    /**
     * Return a function that can be called instead of `callback`, but guarantees
     * a limited execution rate.
     * The execution rate is calculated based on the runtime duration of the
     * previous call.
     * Example:
     * ```js
     * throttledFoo = util.adaptiveThrottle(foo.bind(this), {});
     * throttledFoo();
     * throttledFoo();
     * ```
     */
    function adaptiveThrottle(callback, options) {
        const opts = Object.assign({
            minDelay: 16,
            defaultDelay: 200,
            maxDelay: 5000,
            delayFactor: 2.0,
        }, options);
        const minDelay = Math.max(16, +opts.minDelay);
        const maxDelay = +opts.maxDelay;
        let waiting = 0; // Initially, we're not waiting
        let pendingArgs = null;
        let pendingTimer = null;
        const throttledFn = (...args) => {
            if (waiting) {
                pendingArgs = args;
                // console.log(`adaptiveThrottle() queing request #${waiting}...`, args);
                waiting += 1;
            }
            else {
                // Prevent invocations while running or blocking
                waiting = 1;
                const useArgs = args; // pendingArgs || args;
                pendingArgs = null;
                // console.log(`adaptiveThrottle() execute...`, useArgs);
                const start = Date.now();
                try {
                    callback.apply(this, useArgs);
                }
                catch (error) {
                    console.error(error); // eslint-disable-line no-console
                }
                const elap = Date.now() - start;
                const curDelay = Math.min(Math.max(minDelay, elap * opts.delayFactor), maxDelay);
                const useDelay = Math.max(minDelay, curDelay - elap);
                // console.log(
                //   `adaptiveThrottle() calling worker took ${elap}ms. delay = ${curDelay}ms, using ${useDelay}ms`,
                //   pendingArgs
                // );
                pendingTimer = setTimeout(() => {
                    // Unblock, and trigger pending requests if any
                    // const skipped = waiting - 1;
                    pendingTimer = null;
                    waiting = 0; // And allow future invocations
                    if (pendingArgs != null) {
                        // There was another request while running or waiting
                        // console.log(
                        //   `adaptiveThrottle() re-trigger (missed ${skipped})...`,
                        //   pendingArgs
                        // );
                        throttledFn.apply(this, pendingArgs);
                    }
                }, useDelay);
            }
        };
        throttledFn.cancel = () => {
            if (pendingTimer) {
                clearTimeout(pendingTimer);
                pendingTimer = null;
            }
            pendingArgs = null;
            waiting = 0;
        };
        throttledFn.pending = () => {
            return !!pendingTimer;
        };
        throttledFn.flush = () => {
            throw new Error("Not implemented");
        };
        return throttledFn;
    }

    var util = /*#__PURE__*/Object.freeze({
        __proto__: null,
        Deferred: Deferred$1,
        MAX_INT: MAX_INT,
        MOUSE_BUTTONS: MOUSE_BUTTONS,
        ValidationError: ValidationError,
        adaptiveThrottle: adaptiveThrottle,
        assert: assert,
        debounce: debounce,
        documentReady: documentReady,
        documentReadyPromise: documentReadyPromise,
        each: each,
        elemFromHtml: elemFromHtml,
        elemFromSelector: elemFromSelector,
        error: error,
        escapeHtml: escapeHtml,
        escapeRegex: escapeRegex,
        escapeTooltip: escapeTooltip,
        eventToString: eventToString,
        extend: extend,
        extractHtmlText: extractHtmlText,
        getOption: getOption,
        getValueFromElem: getValueFromElem,
        isArray: isArray,
        isEmptyObject: isEmptyObject,
        isFunction: isFunction,
        isMac: isMac,
        isPlainObject: isPlainObject,
        noop: noop,
        onEvent: onEvent,
        overrideMethod: overrideMethod,
        setElemDisplay: setElemDisplay,
        setTimeoutPromise: setTimeoutPromise,
        setValueToElem: setValueToElem,
        sleep: sleep,
        throttle: throttle,
        toSet: toSet,
        toggleCheckbox: toggleCheckbox,
        type: type
    });

    /*!
     * Wunderbaum - types
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    /**
     * Possible values for {@link WunderbaumNode.update()} and {@link Wunderbaum.update()}.
     */
    var ChangeType;
    (function (ChangeType) {
        /** Re-render the whole viewport, headers, and all rows. */
        ChangeType["any"] = "any";
        /** A node's title, icon, columns, or status have changed. Update the existing row markup. */
        ChangeType["data"] = "data";
        /** The `tree.columns` definition has changed beyond simple width adjustments. */
        ChangeType["colStructure"] = "colStructure";
        /** The viewport/window was resized. Adjust layout attributes for all elements. */
        ChangeType["resize"] = "resize";
        /** A node's definition has changed beyond status and data. Re-render the whole row's markup. */
        ChangeType["row"] = "row";
        /** Nodes have been added, removed, etc. Update markup. */
        ChangeType["structure"] = "structure";
        /** A node's status has changed. Update current row's classes, to reflect active, selected, ... */
        ChangeType["status"] = "status";
        /** Vertical scroll event. Update the 'top' property of all rows. */
        ChangeType["scroll"] = "scroll";
    })(ChangeType || (ChangeType = {}));
    /* Internal use. */
    var RenderFlag;
    (function (RenderFlag) {
        RenderFlag["clearMarkup"] = "clearMarkup";
        RenderFlag["header"] = "header";
        RenderFlag["redraw"] = "redraw";
        RenderFlag["scroll"] = "scroll";
    })(RenderFlag || (RenderFlag = {}));
    /** Possible values for {@link WunderbaumNode.setStatus()}. */
    var NodeStatusType;
    (function (NodeStatusType) {
        NodeStatusType["ok"] = "ok";
        NodeStatusType["loading"] = "loading";
        NodeStatusType["error"] = "error";
        NodeStatusType["noData"] = "noData";
        NodeStatusType["paging"] = "paging";
    })(NodeStatusType || (NodeStatusType = {}));
    /** Define the subregion of a node, where an event occurred. */
    var NodeRegion;
    (function (NodeRegion) {
        NodeRegion["unknown"] = "";
        NodeRegion["checkbox"] = "checkbox";
        NodeRegion["column"] = "column";
        NodeRegion["expander"] = "expander";
        NodeRegion["icon"] = "icon";
        NodeRegion["prefix"] = "prefix";
        NodeRegion["title"] = "title";
    })(NodeRegion || (NodeRegion = {}));
    /** Initial navigation mode and possible transition. */
    var NavModeEnum;
    (function (NavModeEnum) {
        NavModeEnum["startRow"] = "startRow";
        NavModeEnum["cell"] = "cell";
        NavModeEnum["startCell"] = "startCell";
        NavModeEnum["row"] = "row";
    })(NavModeEnum || (NavModeEnum = {}));

    /*!
     * Wunderbaum - wb_extension_base
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    class WunderbaumExtension {
        constructor(tree, id, defaults) {
            this.enabled = true;
            this.tree = tree;
            this.id = id;
            this.treeOpts = tree.options;
            const opts = tree.options;
            if (this.treeOpts[id] === undefined) {
                opts[id] = this.extensionOpts = extend({}, defaults);
            }
            else {
                // TODO: do we break existing object instance references here?
                this.extensionOpts = extend({}, defaults, opts[id]);
                opts[id] = this.extensionOpts;
            }
            this.enabled = this.getPluginOption("enabled", true);
        }
        /** Called on tree (re)init after all extensions are added, but before loading.*/
        init() {
            this.tree.element.classList.add("wb-ext-" + this.id);
        }
        // protected callEvent(type: string, extra?: any): any {
        //   let func = this.extensionOpts[type];
        //   if (func) {
        //     return func.call(
        //       this.tree,
        //       util.extend(
        //         {
        //           event: this.id + "." + type,
        //         },
        //         extra
        //       )
        //     );
        //   }
        // }
        getPluginOption(name, defaultValue) {
            var _a;
            return (_a = this.extensionOpts[name]) !== null && _a !== void 0 ? _a : defaultValue;
        }
        setPluginOption(name, value) {
            this.extensionOpts[name] = value;
        }
        setEnabled(flag = true) {
            return this.setPluginOption("enabled", !!flag);
            // this.enabled = !!flag;
        }
        onKeyEvent(data) {
            return;
        }
        onRender(data) {
            return;
        }
    }

    /*!
     * Wunderbaum - ext-filter
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    const START_MARKER = "\uFFF7";
    const END_MARKER = "\uFFF8";
    const RE_START_MARKER = new RegExp(escapeRegex(START_MARKER), "g");
    const RE_END_MARTKER = new RegExp(escapeRegex(END_MARKER), "g");
    class FilterExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "filter", {
                connectInput: null,
                autoApply: true,
                autoExpand: false,
                counter: true,
                fuzzy: false,
                hideExpandedCounter: true,
                hideExpanders: false,
                highlight: true,
                leavesOnly: false,
                mode: "dim",
                noData: true, // Display a 'no data' status node if result is empty
            });
            this.lastFilterArgs = null;
        }
        init() {
            super.init();
            const connectInput = this.getPluginOption("connectInput");
            if (connectInput) {
                this.queryInput = elemFromSelector(connectInput);
                onEvent(this.queryInput, "input", debounce((e) => {
                    // this.tree.log("query", e);
                    this.filterNodes(this.queryInput.value.trim(), {});
                }, 700));
            }
        }
        setPluginOption(name, value) {
            // alert("filter opt=" + name + ", " + value)
            super.setPluginOption(name, value);
            switch (name) {
                case "mode":
                    this.tree.filterMode = value === "hide" ? "hide" : "dim";
                    this.tree.updateFilter();
                    break;
            }
        }
        _applyFilterNoUpdate(filter, branchMode, _opts) {
            return this.tree.runWithDeferredUpdate(() => {
                return this._applyFilterImpl(filter, branchMode, _opts);
            });
        }
        _applyFilterImpl(filter, branchMode, _opts) {
            let match, temp, count = 0;
            const start = Date.now();
            const tree = this.tree;
            const treeOpts = tree.options;
            // escapeTitles = treeOpts.escapeTitles,
            const prevAutoCollapse = treeOpts.autoCollapse;
            const opts = extend({}, treeOpts.filter, _opts);
            const hideMode = opts.mode === "hide";
            const leavesOnly = !!opts.leavesOnly && !branchMode;
            // Default to 'match title substring (case insensitive)'
            if (typeof filter === "string") {
                if (filter === "") {
                    tree.logInfo("Passing an empty string as a filter is handled as clearFilter().");
                    this.clearFilter();
                    return;
                }
                if (opts.fuzzy) {
                    // See https://codereview.stackexchange.com/questions/23899/faster-javascript-fuzzy-string-matching-function/23905#23905
                    // and http://www.quora.com/How-is-the-fuzzy-search-algorithm-in-Sublime-Text-designed
                    // and http://www.dustindiaz.com/autocomplete-fuzzy-matching
                    match = filter
                        .split("")
                        // Escaping the `filter` will not work because,
                        // it gets further split into individual characters. So,
                        // escape each character after splitting
                        .map(escapeRegex)
                        .reduce(function (a, b) {
                        // create capture groups for parts that comes before
                        // the character
                        return a + "([^" + b + "]*)" + b;
                    }, "");
                }
                else {
                    match = escapeRegex(filter); // make sure a '.' is treated literally
                }
                const re = new RegExp(match, "i");
                const reHighlight = new RegExp(escapeRegex(filter), "gi");
                filter = (node) => {
                    if (!node.title) {
                        return false;
                    }
                    // let text = escapeTitles ? node.title : extractHtmlText(node.title);
                    const text = node.title;
                    // `.match` instead of `.test` to get the capture groups
                    const res = text.match(re);
                    if (res && opts.highlight) {
                        // if (escapeTitles) {
                        if (opts.fuzzy) {
                            temp = _markFuzzyMatchedChars(text, res, true);
                        }
                        else {
                            // #740: we must not apply the marks to escaped entity names, e.g. `&quot;`
                            // Use some exotic characters to mark matches:
                            temp = text.replace(reHighlight, function (s) {
                                return START_MARKER + s + END_MARKER;
                            });
                        }
                        // now we can escape the title...
                        node.titleWithHighlight = escapeHtml(temp)
                            // ... and finally insert the desired `<mark>` tags
                            .replace(RE_START_MARKER, "<mark>")
                            .replace(RE_END_MARTKER, "</mark>");
                        // } else {
                        //   if (opts.fuzzy) {
                        //     node.titleWithHighlight = _markFuzzyMatchedChars(text, res);
                        //   } else {
                        //     node.titleWithHighlight = text.replace(reHighlight, function (s) {
                        //       return "<mark>" + s + "</mark>";
                        //     });
                        //   }
                        // }
                        // node.debug("filter", escapeTitles, text, node.titleWithHighlight);
                    }
                    return !!res;
                };
            }
            tree.filterMode = opts.mode;
            // eslint-disable-next-line prefer-rest-params, prefer-spread
            this.lastFilterArgs = arguments;
            tree.element.classList.toggle("wb-ext-filter-hide", !!hideMode);
            tree.element.classList.toggle("wb-ext-filter-dim", !hideMode);
            tree.element.classList.toggle("wb-ext-filter-hide-expanders", !!opts.hideExpanders);
            // Reset current filter
            tree.root.subMatchCount = 0;
            tree.visit((node) => {
                delete node.match;
                delete node.titleWithHighlight;
                node.subMatchCount = 0;
            });
            // statusNode = tree.root.findDirectChild(KEY_NODATA);
            // if (statusNode) {
            //   statusNode.remove();
            // }
            tree.setStatus(NodeStatusType.ok);
            // Adjust node.hide, .match, and .subMatchCount properties
            treeOpts.autoCollapse = false; // #528
            tree.visit((node) => {
                if (leavesOnly && node.children != null) {
                    return;
                }
                let res = filter(node);
                if (res === "skip") {
                    node.visit(function (c) {
                        c.match = false;
                    }, true);
                    return "skip";
                }
                let matchedByBranch = false;
                if ((branchMode || res === "branch") && node.parent.match) {
                    res = true;
                    matchedByBranch = true;
                }
                if (res) {
                    count++;
                    node.match = true;
                    node.visitParents((p) => {
                        if (p !== node) {
                            p.subMatchCount += 1;
                        }
                        // Expand match (unless this is no real match, but only a node in a matched branch)
                        if (opts.autoExpand && !matchedByBranch && !p.expanded) {
                            p.setExpanded(true, {
                                noAnimation: true,
                                noEvents: true,
                            });
                            p._filterAutoExpanded = true;
                        }
                    }, true);
                }
            });
            treeOpts.autoCollapse = prevAutoCollapse;
            if (count === 0 && opts.noData && hideMode) {
                if (typeof opts.noData === "string") {
                    tree.root.setStatus(NodeStatusType.noData, { message: opts.noData });
                }
                else {
                    tree.root.setStatus(NodeStatusType.noData);
                }
            }
            // Redraw whole tree
            tree.logInfo(`Filter '${match}' found ${count} nodes in ${Date.now() - start} ms.`);
            return count;
        }
        /**
         * [ext-filter] Dim or hide nodes.
         */
        filterNodes(filter, options) {
            return this._applyFilterNoUpdate(filter, false, options);
        }
        /**
         * [ext-filter] Dim or hide whole branches.
         */
        filterBranches(filter, options) {
            return this._applyFilterNoUpdate(filter, true, options);
        }
        /**
         * [ext-filter] Re-apply current filter.
         */
        updateFilter() {
            var _a;
            const tree = this.tree;
            if (tree.filterMode &&
                this.lastFilterArgs &&
                ((_a = tree.options.filter) === null || _a === void 0 ? void 0 : _a.autoApply)) {
                // eslint-disable-next-line prefer-spread
                this._applyFilterNoUpdate.apply(this, this.lastFilterArgs);
            }
            else {
                tree.logWarn("updateFilter(): no filter active.");
            }
        }
        /**
         * [ext-filter] Reset the filter.
         */
        clearFilter() {
            const tree = this.tree;
            // statusNode = tree.root.findDirectChild(KEY_NODATA),
            // escapeTitles = tree.options.escapeTitles;
            tree.enableUpdate(false);
            // if (statusNode) {
            //   statusNode.remove();
            // }
            tree.setStatus(NodeStatusType.ok);
            // we also counted root node's subMatchCount
            delete tree.root.match;
            delete tree.root.subMatchCount;
            tree.visit((node) => {
                // if (node.match && node._rowElem) {
                //   let titleElem = node._rowElem.querySelector("span.wb-title")!;
                //   node._callEvent("enhanceTitle", { titleElem: titleElem });
                // }
                delete node.match;
                delete node.subMatchCount;
                delete node.titleWithHighlight;
                // if (node.subMatchBadge) {
                //   node.subMatchBadge.remove();
                //   delete node.subMatchBadge;
                // }
                if (node._filterAutoExpanded && node.expanded) {
                    node.setExpanded(false, {
                        noAnimation: true,
                        noEvents: true,
                    });
                }
                delete node._filterAutoExpanded;
            });
            tree.filterMode = null;
            this.lastFilterArgs = null;
            tree.element.classList.remove(
            // "wb-ext-filter",
            "wb-ext-filter-dim", "wb-ext-filter-hide");
            // tree._callHook("treeStructureChanged", this, "clearFilter");
            tree.enableUpdate(true);
        }
    }
    /**
     * @description Marks the matching charecters of `text` either by `mark` or
     * by exotic*Chars (if `escapeTitles` is `true`) based on `matches`
     * which is an array of matching groups.
     * @param {string} text
     * @param {RegExpMatchArray} matches
     */
    function _markFuzzyMatchedChars(text, matches, escapeTitles = true) {
        const matchingIndices = [];
        // get the indices of matched characters (Iterate through `RegExpMatchArray`)
        for (let _matchingArrIdx = 1; _matchingArrIdx < matches.length; _matchingArrIdx++) {
            const _mIdx =
            // get matching char index by cumulatively adding
            // the matched group length
            matches[_matchingArrIdx].length +
                (_matchingArrIdx === 1 ? 0 : 1) +
                (matchingIndices[matchingIndices.length - 1] || 0);
            matchingIndices.push(_mIdx);
        }
        // Map each `text` char to its position and store in `textPoses`.
        const textPoses = text.split("");
        if (escapeTitles) {
            // If escaping the title, then wrap the matching char within exotic chars
            matchingIndices.forEach(function (v) {
                textPoses[v] = START_MARKER + textPoses[v] + END_MARKER;
            });
        }
        else {
            // Otherwise, Wrap the matching chars within `mark`.
            matchingIndices.forEach(function (v) {
                textPoses[v] = "<mark>" + textPoses[v] + "</mark>";
            });
        }
        // Join back the modified `textPoses` to create final highlight markup.
        return textPoses.join("");
    }

    /*!
     * Wunderbaum - ext-keynav
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    const QUICKSEARCH_DELAY = 500;
    class KeynavExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "keynav", {});
        }
        _getEmbeddedInputElem(elem) {
            var _a;
            let input = null;
            if (elem && elem.type != null) {
                input = elem;
            }
            else {
                // ,[contenteditable]
                const ace = (_a = this.tree.getActiveColElem()) === null || _a === void 0 ? void 0 : _a.querySelector("input,select");
                if (ace) {
                    input = ace;
                }
            }
            return input;
        }
        // /* Return the current cell's embedded input that has keyboard focus. */
        // protected _getFocusedInputElem(): HTMLInputElement | null {
        //   const ace = this.tree
        //     .getActiveColElem()
        //     ?.querySelector<HTMLInputElement>("input:focus,select:focus");
        //   return ace || null;
        // }
        /* Return true if the current cell's embedded input has keyboard focus. */
        _isCurInputFocused() {
            var _a;
            const ace = (_a = this.tree
                .getActiveColElem()) === null || _a === void 0 ? void 0 : _a.querySelector("input:focus,select:focus");
            return !!ace;
        }
        onKeyEvent(data) {
            const event = data.event;
            const tree = this.tree;
            const opts = data.options;
            const activate = !event.ctrlKey || opts.autoActivate;
            const curInput = this._getEmbeddedInputElem(event.target);
            const inputHasFocus = curInput && this._isCurInputFocused();
            const navModeOption = opts.navigationModeOption;
            let focusNode, eventName = eventToString(event), node = data.node, handled = true;
            // tree.log(`onKeyEvent: ${eventName}, curInput`, curInput);
            if (!tree.isEnabled()) {
                // tree.logDebug(`onKeyEvent ignored for disabled tree: ${eventName}`);
                return false;
            }
            // Let callback prevent default processing
            if (tree._callEvent("keydown", data) === false) {
                return false;
            }
            // Let ext-edit trigger editing
            if (tree._callMethod("edit._preprocessKeyEvent", data) === false) {
                return false;
            }
            // Set focus to active (or first node) if no other node has the focus yet
            if (!node) {
                const currentNode = tree.getFocusNode() || tree.getActiveNode();
                const firstNode = tree.getFirstChild();
                if (!currentNode && firstNode && eventName === "ArrowDown") {
                    firstNode.logInfo("Keydown: activate first node.");
                    firstNode.setActive();
                    return;
                }
                focusNode = currentNode || firstNode;
                if (focusNode) {
                    focusNode.setFocus();
                    node = tree.getFocusNode();
                    node.logInfo("Keydown: force focus on active node.");
                }
            }
            const isColspan = node.isColspan();
            if (tree.isRowNav()) {
                // -----------------------------------------------------------------------
                // --- Row Mode ---
                // -----------------------------------------------------------------------
                if (inputHasFocus) {
                    // If editing an embedded input control, let the control handle all
                    // keys. Only Enter and Escape should apply / discard, but keep the
                    // keyboard focus.
                    switch (eventName) {
                        case "Enter":
                            curInput.blur();
                            tree.setFocus();
                            break;
                        case "Escape":
                            node._render();
                            tree.setFocus();
                            break;
                    }
                    return;
                }
                // --- Quick-Search
                if (opts.quicksearch &&
                    eventName.length === 1 &&
                    /^\w$/.test(eventName) &&
                    !curInput) {
                    // Allow to search for longer streaks if typed in quickly
                    const stamp = Date.now();
                    if (stamp - tree.lastQuicksearchTime > QUICKSEARCH_DELAY) {
                        tree.lastQuicksearchTerm = "";
                    }
                    tree.lastQuicksearchTime = stamp;
                    tree.lastQuicksearchTerm += eventName;
                    const matchNode = tree.findNextNode(tree.lastQuicksearchTerm, tree.getActiveNode());
                    if (matchNode) {
                        matchNode.setActive(true, { event: event });
                    }
                    event.preventDefault();
                    return;
                }
                // Pre-Evaluate expand/collapse action for LEFT/RIGHT
                switch (eventName) {
                    case "Enter":
                        if (node.isActive()) {
                            if (node.isExpanded()) {
                                eventName = "Subtract"; // callapse
                            }
                            else if (node.isExpandable(true)) {
                                eventName = "Add"; // expand
                            }
                        }
                        break;
                    case "ArrowLeft":
                        if (node.expanded) {
                            eventName = "Subtract"; // collapse
                        }
                        break;
                    case "ArrowRight":
                        if (!node.expanded && node.isExpandable(true)) {
                            eventName = "Add"; // expand
                        }
                        else if (navModeOption === NavModeEnum.startCell ||
                            navModeOption === NavModeEnum.startRow) {
                            event.preventDefault();
                            tree.setCellNav();
                            return false;
                        }
                        break;
                }
                // Standard navigation (row mode)
                switch (eventName) {
                    case "+":
                    case "Add":
                        // case "=": // 187: '+' @ Chrome, Safari
                        node.setExpanded(true);
                        break;
                    case "-":
                    case "Subtract":
                        node.setExpanded(false);
                        break;
                    case " ": // Space
                        // if (node.isPagingNode()) {
                        //   tree._triggerNodeEvent("clickPaging", ctx, event);
                        // } else
                        if (node.getOption("checkbox")) {
                            node.toggleSelected();
                        }
                        else {
                            node.setActive(true, { event: event });
                        }
                        break;
                    case "Enter":
                        node.setActive(true, { event: event });
                        break;
                    case "ArrowDown":
                    case "ArrowLeft":
                    case "ArrowRight":
                    case "ArrowUp":
                    case "Backspace":
                    case "End":
                    case "Home":
                    case "Control+End":
                    case "Control+Home":
                    case "Meta+ArrowDown":
                    case "Meta+ArrowUp":
                    case "PageDown":
                    case "PageUp":
                        node.navigate(eventName, { activate: activate, event: event });
                        break;
                    default:
                        handled = false;
                }
            }
            else {
                // -----------------------------------------------------------------------
                // --- Cell Mode ---
                // -----------------------------------------------------------------------
                // // Standard navigation (cell mode)
                // if (isCellEditMode && INPUT_BREAKOUT_KEYS.has(eventName)) {
                // }
                // const curInput = this._getEmbeddedInputElem(null);
                const curInputType = curInput ? curInput.type || curInput.tagName : "";
                // const inputHasFocus = curInput && this._isCurInputFocused();
                const inputCanFocus = curInput && curInputType !== "checkbox";
                if (inputHasFocus) {
                    if (eventName === "Escape") {
                        node.logDebug(`Reset focused input on Escape`);
                        // Discard changes and reset input validation state
                        curInput.setCustomValidity("");
                        node._render();
                        // Keep cell-nav mode
                        tree.setFocus();
                        tree.setColumn(tree.activeColIdx);
                        return;
                        // } else if (!INPUT_BREAKOUT_KEYS.has(eventName)) {
                    }
                    else if (eventName !== "Enter") {
                        if (curInput && curInput.checkValidity && !curInput.checkValidity()) {
                            // Invalid input: ignore all keys except Enter and Escape
                            node.logDebug(`Ignored ${eventName} inside invalid input`);
                            return false;
                        }
                        // Let current `<input>` handle it
                        node.logDebug(`Ignored ${eventName} inside focused input`);
                        return;
                    }
                    // const curInputType = curInput.type || curInput.tagName;
                    // const breakoutKeys = INPUT_KEYS[curInputType];
                    // if (!breakoutKeys.includes(eventName)) {
                    //   node.logDebug(`Ignored ${eventName} inside ${curInputType} input`);
                    //   return;
                    // }
                }
                else if (curInput) {
                    // On a cell that has an embedded, unfocused <input>
                    if (eventName.length === 1 && inputCanFocus) {
                        // Typing a single char
                        curInput.focus();
                        curInput.value = "";
                        node.logDebug(`Focus input: ${eventName}`);
                        return false;
                    }
                }
                if (eventName === "Tab") {
                    eventName = "ArrowRight";
                    handled = true;
                }
                else if (eventName === "Shift+Tab") {
                    eventName = tree.activeColIdx > 0 ? "ArrowLeft" : "";
                    handled = true;
                }
                switch (eventName) {
                    case "+":
                    case "Add":
                        // case "=": // 187: '+' @ Chrome, Safari
                        node.setExpanded(true);
                        break;
                    case "-":
                    case "Subtract":
                        node.setExpanded(false);
                        break;
                    case " ": // Space
                        if (tree.activeColIdx === 0 && node.getOption("checkbox")) {
                            node.toggleSelected();
                            handled = true;
                        }
                        else if (curInput && curInputType === "checkbox") {
                            curInput.click();
                            // toggleCheckbox(curInput)
                            // new Event("change")
                            // curInput.change
                            handled = true;
                        }
                        break;
                    case "F2":
                        if (curInput && !inputHasFocus && inputCanFocus) {
                            curInput.focus();
                            handled = true;
                        }
                        break;
                    case "Enter":
                        tree.setFocus(); // Blur prev. input if any
                        if ((tree.activeColIdx === 0 || isColspan) && node.isExpandable()) {
                            node.setExpanded(!node.isExpanded());
                            handled = true;
                        }
                        else if (curInput && !inputHasFocus && inputCanFocus) {
                            curInput.focus();
                            handled = true;
                        }
                        break;
                    case "Escape":
                        tree.setFocus(); // Blur prev. input if any
                        node.log(`keynav: focus tree...`);
                        if (tree.isCellNav() && navModeOption !== NavModeEnum.cell) {
                            node.log(`keynav: setCellNav(false)`);
                            tree.setCellNav(false); // row-nav mode
                            tree.setFocus(); //
                            handled = true;
                        }
                        break;
                    case "ArrowLeft":
                        tree.setFocus(); // Blur prev. input if any
                        if (isColspan && node.isExpanded()) {
                            node.setExpanded(false);
                        }
                        else if (!isColspan && tree.activeColIdx > 0) {
                            tree.setColumn(tree.activeColIdx - 1);
                        }
                        else if (navModeOption !== NavModeEnum.cell) {
                            tree.setCellNav(false); // row-nav mode
                        }
                        handled = true;
                        break;
                    case "ArrowRight":
                        tree.setFocus(); // Blur prev. input if any
                        if (isColspan && !node.isExpanded()) {
                            node.setExpanded();
                        }
                        else if (!isColspan &&
                            tree.activeColIdx < tree.columns.length - 1) {
                            tree.setColumn(tree.activeColIdx + 1);
                        }
                        handled = true;
                        break;
                    case "Home": // Generated by [Fn] + ArrowLeft on Mac
                        // case "Meta+ArrowLeft":
                        tree.setFocus(); // Blur prev. input if any
                        if (!isColspan && tree.activeColIdx > 0) {
                            tree.setColumn(0);
                        }
                        handled = true;
                        break;
                    case "End": // Generated by [Fn] + ArrowRight on Mac
                        // case "Meta+ArrowRight":
                        tree.setFocus(); // Blur prev. input if any
                        if (!isColspan && tree.activeColIdx < tree.columns.length - 1) {
                            tree.setColumn(tree.columns.length - 1);
                        }
                        handled = true;
                        break;
                    case "ArrowDown":
                    case "ArrowUp":
                    case "Backspace":
                    case "Control+End": // Generated by Control + [Fn] + ArrowRight on Mac
                    case "Control+Home": // Generated by Control + [Fn] + Arrowleft on Mac
                    case "Meta+ArrowDown": // [⌘] + ArrowDown on Mac
                    case "Meta+ArrowUp": // [⌘] + ArrowUp on Mac
                    case "PageDown": // Generated by [Fn] + ArrowDown on Mac
                    case "PageUp": // Generated by [Fn] + ArrowUp on Mac
                        node.navigate(eventName, { activate: activate, event: event });
                        // if (isCellEditMode) {
                        //   this._getEmbeddedInputElem(null, true); // set focus to input
                        // }
                        handled = true;
                        break;
                    default:
                        handled = false;
                }
            }
            if (handled) {
                event.preventDefault();
            }
            return;
        }
    }

    /*!
     * Wunderbaum - ext-logger
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    class LoggerExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "logger", {});
            this.ignoreEvents = new Set([
                "iconBadge",
                // "enhanceTitle",
                "render",
                "discard",
            ]);
            this.prefix = tree + ".ext-logger";
        }
        init() {
            const tree = this.tree;
            // this.ignoreEvents.add();
            if (tree.getOption("debugLevel") >= 4) {
                // const self = this;
                const ignoreEvents = this.ignoreEvents;
                const prefix = this.prefix;
                overrideMethod(tree, "callEvent", function (name, extra) {
                    /* eslint-disable prefer-rest-params */
                    if (ignoreEvents.has(name)) {
                        return tree._superApply(arguments);
                    }
                    const start = Date.now();
                    const res = tree._superApply(arguments);
                    tree.logDebug(`${prefix}: callEvent('${name}') took ${Date.now() - start} ms.`, arguments[1]);
                    return res;
                });
            }
        }
        onKeyEvent(data) {
            // this.tree.logInfo("onKeyEvent", eventToString(data.event), data);
            this.tree.logDebug(`${this.prefix}: onKeyEvent()`, data);
            return;
        }
    }

    /*!
     * Wunderbaum - common
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    const DEFAULT_DEBUGLEVEL = 3; // Replaced by rollup script
    /**
     * Fixed height of a row in pixel. Must match the SCSS variable `$row-outer-height`.
     */
    const ROW_HEIGHT = 22;
    /**
     * Fixed width of node icons in pixel. Must match the SCSS variable `$icon-outer-width`.
     */
    const ICON_WIDTH = 20;
    /**
     * Adjust the width of the title span, so overflow ellipsis work.
     * (2 x `$col-padding-x` + 3px rounding errors).
     */
    const TITLE_SPAN_PAD_Y = 7;
    /** Render row markup for N nodes above and below the visible viewport. */
    const RENDER_MAX_PREFETCH = 5;
    /** Regular expression to detect if a string describes an image URL (in contrast
     * to a class name). Strings are considered image urls if they contain '.' or '/'.
     */
    const TEST_IMG = new RegExp(/\.|\//);
    // export const RECURSIVE_REQUEST_ERROR = "$recursive_request";
    // export const INVALID_REQUEST_TARGET_ERROR = "$request_target_invalid";
    /**
     * Default node icons.
     * Requires bootstrap icons https://icons.getbootstrap.com
     */
    const iconMaps = {
        bootstrap: {
            error: "bi bi-exclamation-triangle",
            // loading: "bi bi-hourglass-split wb-busy",
            loading: "bi bi-chevron-right wb-busy",
            // loading: "bi bi-arrow-repeat wb-spin",
            // loading: '<div class="spinner-border spinner-border-sm" role="status"> <span class="visually-hidden">Loading...</span> </div>',
            // noData: "bi bi-search",
            noData: "bi bi-question-circle",
            expanderExpanded: "bi bi-chevron-down",
            // expanderExpanded: "bi bi-dash-square",
            expanderCollapsed: "bi bi-chevron-right",
            // expanderCollapsed: "bi bi-plus-square",
            expanderLazy: "bi bi-chevron-right wb-helper-lazy-expander",
            // expanderLazy: "bi bi-chevron-bar-right",
            checkChecked: "bi bi-check-square",
            checkUnchecked: "bi bi-square",
            checkUnknown: "bi bi-dash-square-dotted",
            radioChecked: "bi bi-circle-fill",
            radioUnchecked: "bi bi-circle",
            radioUnknown: "bi bi-record-circle",
            folder: "bi bi-folder2",
            folderOpen: "bi bi-folder2-open",
            folderLazy: "bi bi-folder-symlink",
            doc: "bi bi-file-earmark",
        },
        fontawesome6: {
            error: "fa-solid fa-triangle-exclamation",
            loading: "fa-solid fa-chevron-right fa-beat",
            noData: "fa-solid fa-circle-question",
            expanderExpanded: "fa-solid fa-chevron-down",
            expanderCollapsed: "fa-solid fa-chevron-right",
            expanderLazy: "fa-solid fa-chevron-right wb-helper-lazy-expander",
            checkChecked: "fa-regular fa-square-check",
            checkUnchecked: "fa-regular fa-square",
            checkUnknown: "fa-regular fa-square-minus",
            radioChecked: "fa-solid fa-circle",
            radioUnchecked: "fa-regular fa-circle",
            radioUnknown: "fa-regular fa-circle-question",
            folder: "fa-solid fa-folder-closed",
            folderOpen: "fa-regular fa-folder-open",
            folderLazy: "fa-solid fa-folder-plus",
            doc: "fa-regular fa-file",
        },
    };
    /** Dict keys that are evaluated by source loader (others are added to `tree.data` instead). */
    const RESERVED_TREE_SOURCE_KEYS = new Set([
        "_format",
        "_keyMap",
        "_positional",
        "_typeList",
        "_valueMap",
        "_version",
        "children",
        "columns",
        "types",
    ]);
    // /** Key codes that trigger grid navigation, even when inside an input element. */
    // export const INPUT_BREAKOUT_KEYS: Set<string> = new Set([
    //   // "ArrowDown",
    //   // "ArrowUp",
    //   "Enter",
    //   "Escape",
    // ]);
    /** Map `KeyEvent.key` to navigation action. */
    const KEY_TO_ACTION_DICT = {
        " ": "toggleSelect",
        "+": "expand",
        Add: "expand",
        ArrowDown: "down",
        ArrowLeft: "left",
        ArrowRight: "right",
        ArrowUp: "up",
        Backspace: "parent",
        "/": "collapseAll",
        Divide: "collapseAll",
        End: "lastCol",
        Home: "firstCol",
        "Control+End": "last",
        "Control+Home": "first",
        "Meta+ArrowDown": "last",
        "Meta+ArrowUp": "first",
        "*": "expandAll",
        Multiply: "expandAll",
        PageDown: "pageDown",
        PageUp: "pageUp",
        "-": "collapse",
        Subtract: "collapse",
    };
    /** Return a callback that returns true if the node title matches the string
     * or regular expression.
     * @see {@link WunderbaumNode.findAll()}
     */
    function makeNodeTitleMatcher(match) {
        if (match instanceof RegExp) {
            return function (node) {
                return match.test(node.title);
            };
        }
        assert(typeof match === "string", `Expected a string or RegExp: ${match}`);
        // s = escapeRegex(s.toLowerCase());
        return function (node) {
            return node.title === match;
            // console.log("match " + node, node.title.toLowerCase().indexOf(match))
            // return node.title.toLowerCase().indexOf(match) >= 0;
        };
    }
    /** Return a callback that returns true if the node title starts with a string (case-insensitive). */
    function makeNodeTitleStartMatcher(s) {
        s = escapeRegex(s);
        const reMatch = new RegExp("^" + s, "i");
        return function (node) {
            return reMatch.test(node.title);
        };
    }
    /** Compare two nodes by title (case-insensitive). */
    function nodeTitleSorter(a, b) {
        const x = a.title.toLowerCase();
        const y = b.title.toLowerCase();
        return x === y ? 0 : x > y ? 1 : -1;
    }
    /**
     * Convert 'flat' to 'nested' format.
     *
     *  Flat node entry format:
     *    [PARENT_ID, [POSITIONAL_ARGS]]
     *  or
     *    [PARENT_ID, [POSITIONAL_ARGS], {KEY_VALUE_ARGS}]
     *
     * 1. Parent-referencing list is converted to a list of nested dicts with
     *    optional `children` properties.
     * 2. `[POSITIONAL_ARGS]` are added as dict attributes.
     */
    function unflattenSource(source) {
        var _a, _b, _c;
        const { _format, _keyMap = {}, _positional = [], children } = source;
        if (_format !== "flat") {
            throw new Error(`Expected source._format: "flat", but got ${_format}`);
        }
        if (_positional && _positional.includes("children")) {
            throw new Error(`source._positional must not include "children": ${_positional}`);
        }
        let longToShort = _keyMap;
        if (_keyMap.t) {
            // Inverse keyMap was used (pre 0.7.0)
            // TODO: raise Error on final 1.x release
            const msg = `source._keyMap maps from long to short since v0.7.0. Flip key/value!`;
            console.warn(msg); // eslint-disable-line no-console
            longToShort = {};
            for (const [key, value] of Object.entries(_keyMap)) {
                longToShort[value] = key;
            }
        }
        const positionalShort = _positional.map((e) => longToShort[e]);
        const newChildren = [];
        const keyToNodeMap = {};
        const indexToNodeMap = {};
        const keyAttrName = (_a = longToShort["key"]) !== null && _a !== void 0 ? _a : "key";
        const childrenAttrName = (_b = longToShort["children"]) !== null && _b !== void 0 ? _b : "children";
        for (const [index, nodeTuple] of children.entries()) {
            // Node entry format:
            //   [PARENT_ID, [POSITIONAL_ARGS]]
            // or
            //   [PARENT_ID, [POSITIONAL_ARGS], {KEY_VALUE_ARGS}]
            const [parentId, args, kwargs = {}] = nodeTuple;
            // Free up some memory as we go
            nodeTuple[1] = null;
            if (nodeTuple[2] != null) {
                nodeTuple[2] = null;
            }
            // console.log("flatten", parentId, args, kwargs)
            // We keep `kwargs` as our new node definition. Then we add all positional
            // values to this object:
            args.forEach((val, positionalIdx) => {
                kwargs[positionalShort[positionalIdx]] = val;
            });
            // Find the parent node. `null` means 'toplevel'. PARENT_ID may be the numeric
            // index of the source.children list. If PARENT_ID is a string, we search
            // a parent with node.key of this value.
            indexToNodeMap[index] = kwargs;
            const key = kwargs[keyAttrName];
            if (key != null) {
                keyToNodeMap[key] = kwargs;
            }
            let parentNode = null;
            if (parentId === null) ;
            else if (typeof parentId === "number") {
                parentNode = indexToNodeMap[parentId];
                if (parentNode === undefined) {
                    throw new Error(`unflattenSource: Could not find parent node by index: ${parentId}.`);
                }
            }
            else {
                parentNode = keyToNodeMap[parentId];
                if (parentNode === undefined) {
                    throw new Error(`unflattenSource: Could not find parent node by key: ${parentId}`);
                }
            }
            if (parentNode) {
                (_c = parentNode[childrenAttrName]) !== null && _c !== void 0 ? _c : (parentNode[childrenAttrName] = []);
                parentNode[childrenAttrName].push(kwargs);
            }
            else {
                newChildren.push(kwargs);
            }
        }
        source.children = newChildren;
    }
    /**
     * Decompresses the source data by
     * - converting from 'flat' to 'nested' format
     * - expanding short alias names to long names (if defined in _keyMap)
     * - resolving value indexes to value strings (if defined in _valueMap)
     *
     * @param source - The source object to be decompressed.
     * @returns void
     */
    function decompressSourceData(source) {
        let { _format, _version = 1, _keyMap, _valueMap } = source;
        assert(_version === 1, `Expected file version 1 instead of ${_version}`);
        let longToShort = _keyMap;
        let shortToLong = {};
        if (longToShort) {
            for (const [key, value] of Object.entries(longToShort)) {
                shortToLong[value] = key;
            }
        }
        // Fallback for old format (pre 0.7.0, using _keyMap in reverse direction)
        // TODO: raise Error on final 1.x release
        if (longToShort && longToShort.t) {
            const msg = `source._keyMap maps from long to short since v0.7.0. Flip key/value!`;
            console.warn(msg); // eslint-disable-line no-console
            [longToShort, shortToLong] = [shortToLong, longToShort];
        }
        // Fallback for old format (pre 0.7.0, using _typeList instead of _valueMap)
        // TODO: raise Error on final 1.x release
        if (source._typeList != null) {
            const msg = `source._typeList is deprecated since v0.7.0: use source._valueMap: {"type": [...]} instead.`;
            if (_valueMap != null) {
                throw new Error(msg);
            }
            else {
                console.warn(msg); // eslint-disable-line no-console
                _valueMap = { type: source._typeList };
                delete source._typeList;
            }
        }
        if (_format === "flat") {
            unflattenSource(source);
        }
        delete source._format;
        delete source._version;
        delete source._keyMap;
        delete source._valueMap;
        delete source._positional;
        function _iter(childList) {
            for (const node of childList) {
                // Iterate over a list of names, because we modify inside the loop
                // (for ... of ... does not allow this)
                Object.getOwnPropertyNames(node).forEach((propName) => {
                    const value = node[propName];
                    // Replace short names with long names if defined in _keyMap
                    let longName = propName;
                    if (_keyMap && shortToLong[propName] != null) {
                        longName = shortToLong[propName];
                        if (longName !== propName) {
                            node[longName] = value;
                            delete node[propName];
                        }
                    }
                    // Replace type index with type name if defined in _valueMap
                    if (_valueMap &&
                        typeof value === "number" &&
                        _valueMap[longName] != null) {
                        const newValue = _valueMap[longName][value];
                        if (newValue == null) {
                            throw new Error(`Expected valueMap[${longName}][${value}] entry in [${_valueMap[longName]}]`);
                        }
                        node[longName] = newValue;
                    }
                });
                // Recursion
                if (node.children) {
                    _iter(node.children);
                }
            }
        }
        if (_keyMap || _valueMap) {
            _iter(source.children);
        }
    }

    /*!
     * Wunderbaum - ext-dnd
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    const nodeMimeType = "application/x-wunderbaum-node";
    class DndExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "dnd", {
                autoExpandMS: 1500,
                // dropMarkerInsertOffsetX: -16, // Additional offset for drop-marker with hitMode = "before"/"after"
                // dropMarkerOffsetX: -24, // Absolute position offset for .fancytree-drop-marker relatively to ..fancytree-title (icon/img near a node accepting drop)
                // #1021 `document.body` is not available yet
                // dropMarkerParent: "body", // Root Container used for drop marker (could be a shadow root)
                multiSource: false,
                effectAllowed: "all",
                dropEffectDefault: "move",
                guessDropEffect: true,
                preventForeignNodes: false,
                preventLazyParents: true,
                preventNonNodes: false,
                preventRecursion: true,
                preventSameParent: false,
                preventVoidMoves: true,
                serializeClipboardData: true,
                scroll: true,
                scrollSensitivity: 20,
                // scrollnterval: 50, // Generate event every 50 ms
                scrollSpeed: 5,
                // setTextTypeJson: false, // Allow dragging of nodes to different IE windows
                sourceCopyHook: null,
                // Events (drag support)
                dragStart: null,
                drag: null,
                dragEnd: null,
                // Events (drop support)
                dragEnter: null,
                dragOver: null,
                dragExpand: null,
                drop: null,
                dragLeave: null, // Callback(targetNode, data)
            });
            // public dropMarkerElem?: HTMLElement;
            this.srcNode = null;
            this.lastTargetNode = null;
            this.lastEnterStamp = 0;
            this.lastAllowedDropRegions = null;
            this.lastDropEffect = null;
            this.lastDropRegion = false;
            this.currentScrollDir = 0;
            this.applyScrollDirThrottled = throttle(this._applyScrollDir, 50);
        }
        init() {
            super.init();
            // Store the current scroll parent, which may be the tree
            // container, any enclosing div, or the document.
            // #761: scrollParent() always needs a container child
            // $temp = $("<span>").appendTo(this.$container);
            // this.$scrollParent = $temp.scrollParent();
            // $temp.remove();
            const tree = this.tree;
            const dndOpts = tree.options.dnd;
            // Enable drag support if dragStart() is specified:
            if (dndOpts.dragStart) {
                onEvent(tree.element, "dragstart drag dragend", this.onDragEvent.bind(this));
            }
            // Enable drop support if dragEnter() is specified:
            if (dndOpts.dragEnter) {
                onEvent(tree.element, "dragenter dragover dragleave drop", this.onDropEvent.bind(this));
            }
        }
        /** Cleanup classes after target node is no longer hovered. */
        _leaveNode() {
            // We remove the marker on dragenter from the previous target:
            const ltn = this.lastTargetNode;
            this.lastEnterStamp = 0;
            if (ltn) {
                ltn.setClass("wb-drop-target wb-drop-over wb-drop-after wb-drop-before", false);
                this.lastTargetNode = null;
            }
        }
        /** */
        unifyDragover(res) {
            if (res === false) {
                return false;
            }
            else if (res instanceof Set) {
                return res.size > 0 ? res : false;
            }
            else if (res === true) {
                return new Set(["over", "before", "after"]);
            }
            else if (typeof res === "string" || isArray(res)) {
                res = toSet(res);
                return res.size > 0 ? res : false;
            }
            throw new Error("Unsupported drop region definition: " + res);
        }
        /**
         * Calculates the drop region based on the drag event and the allowed drop regions.
         */
        _calcDropRegion(e, allowed) {
            const dy = e.offsetY;
            if (!allowed) {
                return false;
            }
            else if (allowed.size === 3) {
                return dy < 0.25 * ROW_HEIGHT
                    ? "before"
                    : dy > 0.75 * ROW_HEIGHT
                        ? "after"
                        : "over";
            }
            else if (allowed.size === 1 && allowed.has("over")) {
                return "over";
            }
            else {
                // Only 'before' and 'after':
                return dy > ROW_HEIGHT / 2 ? "after" : "before";
            }
            // return "over";
        }
        /**
         * Guess drop effect (copy/link/move) using opinionated conventions.
         *
         * Default: dnd.dropEffectDefault
         */
        _guessDropEffect(e) {
            // const nativeDropEffect = e.dataTransfer?.dropEffect;
            var _a;
            // if (nativeDropEffect && nativeDropEffect !== "none") {
            //   return nativeDropEffect;
            // }
            const dndOpts = this.treeOpts.dnd;
            const ea = (_a = dndOpts.effectAllowed) !== null && _a !== void 0 ? _a : "all";
            const canCopy = ["all", "copy", "copyLink", "copyMove"].includes(ea);
            const canLink = ["all", "link", "copyLink", "linkMove"].includes(ea);
            const canMove = ["all", "move", "copyMove", "linkMove"].includes(ea);
            let res = dndOpts.dropEffectDefault;
            if (dndOpts.guessDropEffect) {
                if (isMac) {
                    if (e.altKey && canCopy) {
                        res = "copy";
                    }
                    if (e.metaKey && canMove) {
                        res = "move"; // command key
                    }
                    if (e.altKey && e.metaKey && canLink) {
                        res = "link";
                    }
                }
                else {
                    if (e.ctrlKey && canCopy) {
                        res = "copy";
                    }
                    if (e.shiftKey && canMove) {
                        res = "move";
                    }
                    if (e.altKey && canLink) {
                        res = "link";
                    }
                }
            }
            return res;
        }
        /** Don't allow void operation ('drop on self').*/
        _isVoidDrop(targetNode, srcNode, dropRegion) {
            // this.tree.logDebug(
            //   `_isVoidDrop: ${srcNode} -> ${dropRegion} ${targetNode}`
            // );
            // TODO: should be checked on  move only
            if (!this.treeOpts.dnd.preventVoidMoves || !srcNode) {
                return false;
            }
            if ((dropRegion === "before" && targetNode === srcNode.getNextSibling()) ||
                (dropRegion === "after" && targetNode === srcNode.getPrevSibling())) {
                // this.tree.logDebug("Prevented before/after self");
                return true;
            }
            // Don't allow dropping nodes on own parent (or self)
            return srcNode === targetNode || srcNode.parent === targetNode;
        }
        /* Implement auto scrolling when drag cursor is in top/bottom area of scroll parent. */
        _applyScrollDir() {
            if (this.isDragging() && this.currentScrollDir) {
                const dndOpts = this.tree.options.dnd;
                const sp = this.tree.element; // scroll parent
                const scrollTop = sp.scrollTop;
                if (this.currentScrollDir < 0) {
                    sp.scrollTop = Math.max(0, scrollTop - dndOpts.scrollSpeed);
                }
                else if (this.currentScrollDir > 0) {
                    sp.scrollTop = scrollTop + dndOpts.scrollSpeed;
                }
            }
        }
        /* Implement auto scrolling when drag cursor is in top/bottom area of scroll parent. */
        _autoScroll(viewportY) {
            const tree = this.tree;
            const dndOpts = tree.options.dnd;
            const sensitivity = dndOpts.scrollSensitivity;
            const sp = tree.element; // scroll parent
            const headerHeight = tree.headerElement.clientHeight; // May be 0
            // const height = sp.clientHeight - headerHeight;
            // const height = sp.offsetHeight + headerHeight;
            const height = sp.offsetHeight;
            const scrollTop = sp.scrollTop;
            // tree.logDebug(
            //   `autoScroll: height=${height}, scrollTop=${scrollTop}, viewportY=${viewportY}`
            // );
            this.currentScrollDir = 0;
            if (scrollTop > 0 &&
                viewportY > 0 &&
                viewportY <= sensitivity + headerHeight) {
                // Mouse in top 20px area: scroll up
                // sp.scrollTop = Math.max(0, scrollTop - dndOpts.scrollSpeed);
                this.currentScrollDir = -1;
            }
            else if (scrollTop < sp.scrollHeight - height &&
                viewportY >= height - sensitivity) {
                // Mouse in bottom 20px area: scroll down
                // sp.scrollTop = scrollTop + dndOpts.scrollSpeed;
                this.currentScrollDir = +1;
            }
            if (this.currentScrollDir) {
                this.applyScrollDirThrottled();
            }
            return sp.scrollTop - scrollTop;
        }
        /** Return true if a drag operation currently in progress. */
        isDragging() {
            return !!this.srcNode;
        }
        /**
         * Handle dragstart, drag and dragend events for the source node.
         */
        onDragEvent(e) {
            var _a;
            // const tree = this.tree;
            const dndOpts = this.treeOpts.dnd;
            const srcNode = Wunderbaum.getNode(e);
            if (!srcNode) {
                this.tree.logWarn(`onDragEvent.${e.type}: no node`);
                return;
            }
            if (["dragstart", "dragend"].includes(e.type)) {
                this.tree.logDebug(`onDragEvent.${e.type} srcNode: ${srcNode}`, e);
            }
            // --- dragstart ---
            if (e.type === "dragstart") {
                // Set a default definition of allowed effects
                e.dataTransfer.effectAllowed = dndOpts.effectAllowed; //"copyMove"; // "all";
                if (srcNode.isEditingTitle()) {
                    srcNode.logDebug("Prevented dragging node in edit mode.");
                    e.preventDefault();
                    return false;
                }
                // Let user cancel the drag operation, override effectAllowed, etc.:
                const res = srcNode._callEvent("dnd.dragStart", { event: e });
                if (!res) {
                    e.preventDefault();
                    return false;
                }
                const nodeData = srcNode.toDict(true, (n) => {
                    // We don't want to re-use the key on drop:
                    n._orgKey = n.key;
                    delete n.key;
                });
                nodeData._treeId = srcNode.tree.id;
                if (dndOpts.serializeClipboardData) {
                    if (typeof dndOpts.serializeClipboardData === "function") {
                        e.dataTransfer.setData(nodeMimeType, dndOpts.serializeClipboardData(nodeData, srcNode));
                    }
                    else {
                        e.dataTransfer.setData(nodeMimeType, JSON.stringify(nodeData));
                    }
                }
                // e.dataTransfer!.setData("text/html", $(node.span).html());
                if (!((_a = e.dataTransfer) === null || _a === void 0 ? void 0 : _a.types.includes("text/plain"))) {
                    e.dataTransfer.setData("text/plain", srcNode.title);
                }
                this.srcNode = srcNode;
                setTimeout(() => {
                    // Decouple this call, so the CSS is applied to the node, but not to
                    // the system generated drag image
                    srcNode.setClass("wb-drag-source");
                }, 0);
                // --- drag ---
            }
            else if (e.type === "drag") {
                if (dndOpts.drag) {
                    srcNode._callEvent("dnd.drag", { event: e });
                }
                // --- dragend ---
            }
            else if (e.type === "dragend") {
                srcNode.setClass("wb-drag-source", false);
                this.srcNode = null;
                if (this.lastTargetNode) {
                    this._leaveNode();
                }
                srcNode._callEvent("dnd.dragEnd", { event: e });
            }
            return true;
        }
        /**
         * Handle dragenter, dragover, dragleave, drop events.
         */
        onDropEvent(e) {
            var _a;
            // const isLink = event.dataTransfer.types.includes("text/uri-list");
            const srcNode = this.srcNode;
            const srcTree = srcNode ? srcNode.tree : null;
            const targetNode = Wunderbaum.getNode(e);
            const dndOpts = this.treeOpts.dnd;
            const dt = e.dataTransfer;
            const dropRegion = this._calcDropRegion(e, this.lastAllowedDropRegions);
            /** Helper to log a message if predicate is false. */
            const _t = (pred, msg) => {
                if (pred) {
                    this.tree.log(`Prevented drop operation (${msg}).`);
                }
                return pred;
            };
            if (!targetNode) {
                this._leaveNode();
                return;
            }
            if (["drop"].includes(e.type)) {
                this.tree.logDebug(`onDropEvent.${e.type} targetNode: ${targetNode}, ea: ${dt === null || dt === void 0 ? void 0 : dt.effectAllowed}, ` +
                    `de: ${dt === null || dt === void 0 ? void 0 : dt.dropEffect}, cy: ${e.offsetY}, r: ${dropRegion}, srcNode: ${srcNode}`, e);
            }
            // --- dragenter ---
            if (e.type === "dragenter") {
                // this.tree.logWarn(` onDropEvent.${e.type} targetNode: ${targetNode}`, e);
                this.lastAllowedDropRegions = null;
                // `dragleave` is not reliable with event delegation, so we generate it
                // from dragenter:
                if (this.lastTargetNode && this.lastTargetNode !== targetNode) {
                    this._leaveNode();
                }
                this.lastTargetNode = targetNode;
                this.lastEnterStamp = Date.now();
                if (
                // Don't drop on status node:
                _t(targetNode.isStatusNode(), "is status node") ||
                    // Prevent dropping nodes from different Wunderbaum trees:
                    _t(dndOpts.preventForeignNodes && targetNode.tree !== srcTree, "preventForeignNodes") ||
                    // Prevent dropping items on unloaded lazy Wunderbaum tree nodes:
                    _t(dndOpts.preventLazyParents && !targetNode.isLoaded(), "preventLazyParents") ||
                    // Prevent dropping items other than Wunderbaum tree nodes:
                    _t(dndOpts.preventNonNodes && !srcNode, "preventNonNodes") ||
                    // Prevent dropping nodes on own descendants:
                    _t(dndOpts.preventRecursion && (srcNode === null || srcNode === void 0 ? void 0 : srcNode.isAncestorOf(targetNode)), "preventRecursion") ||
                    // Prevent dropping nodes under same direct parent:
                    _t(dndOpts.preventSameParent &&
                        srcNode &&
                        targetNode.parent === srcNode.parent, "preventSameParent") ||
                    // Don't allow void operation ('drop on self'): TODO: should be checked on  move only
                    _t(dndOpts.preventVoidMoves && targetNode === srcNode, "preventVoidMoves")) {
                    dt.dropEffect = "none";
                    // this.tree.log("Prevented drop operation");
                    return true; // Prevent drop operation
                }
                // User may return a set of regions (or `false` to prevent drop)
                // Figure out a drop effect (copy/link/move) using opinated conventions.
                dt.dropEffect = this._guessDropEffect(e) || "none";
                let regionSet = targetNode._callEvent("dnd.dragEnter", {
                    event: e,
                    sourceNode: srcNode,
                });
                //
                regionSet = this.unifyDragover(regionSet);
                if (!regionSet) {
                    dt.dropEffect = "none";
                    return true; // Prevent drop operation
                }
                this.lastAllowedDropRegions = regionSet;
                this.lastDropEffect = dt.dropEffect;
                targetNode.setClass("wb-drop-target");
                e.preventDefault(); // Allow drop (Drop operation is denied by default)
                return false;
                // --- dragover ---
            }
            else if (e.type === "dragover") {
                const viewportY = e.clientY - this.tree.element.offsetTop;
                this._autoScroll(viewportY);
                dt.dropEffect = this._guessDropEffect(e) || "none";
                targetNode._callEvent("dnd.dragOver", { event: e, sourceNode: srcNode });
                const region = this._calcDropRegion(e, this.lastAllowedDropRegions);
                this.lastDropRegion = region;
                this.lastDropEffect = dt.dropEffect;
                if (dndOpts.autoExpandMS > 0 &&
                    targetNode.isExpandable(true) &&
                    !targetNode._isLoading &&
                    Date.now() - this.lastEnterStamp > dndOpts.autoExpandMS &&
                    targetNode._callEvent("dnd.dragExpand", {
                        event: e,
                        sourceNode: srcNode,
                    }) !== false) {
                    targetNode.setExpanded();
                }
                if (!region || this._isVoidDrop(targetNode, srcNode, region)) {
                    return; // We already rejected in dragenter
                }
                targetNode.setClass("wb-drop-over", region === "over");
                targetNode.setClass("wb-drop-before", region === "before");
                targetNode.setClass("wb-drop-after", region === "after");
                e.preventDefault(); // Allow drop (Drop operation is denied by default)
                return false;
                // --- dragleave ---
            }
            else if (e.type === "dragleave") {
                // NOTE: we cannot trust this event, since it is always fired,
                // Instead we remove the marker on dragenter
                targetNode._callEvent("dnd.dragLeave", { event: e, sourceNode: srcNode });
                // --- drop ---
            }
            else if (e.type === "drop") {
                e.stopPropagation(); // prevent browser from opening links?
                e.preventDefault(); // #69 prevent iOS browser from opening links
                this._leaveNode();
                const region = this.lastDropRegion;
                let nodeData = (_a = e.dataTransfer) === null || _a === void 0 ? void 0 : _a.getData(nodeMimeType);
                nodeData = nodeData ? JSON.parse(nodeData) : null;
                const srcNode = this.srcNode;
                const lastDropEffect = this.lastDropEffect;
                setTimeout(() => {
                    // Decouple this call, because drop actions may prevent the dragend event
                    // from being fired on some browsers
                    targetNode._callEvent("dnd.drop", {
                        event: e,
                        region: region,
                        suggestedDropMode: region === "over" ? "appendChild" : region,
                        suggestedDropEffect: lastDropEffect,
                        // suggestedDropEffect: e.dataTransfer?.dropEffect,
                        sourceNode: srcNode,
                        sourceNodeData: nodeData,
                    });
                }, 10);
            }
            return false;
        }
    }

    /*!
     * Wunderbaum - drag_observer
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    /**
     * Convert mouse- and touch events to 'dragstart', 'drag', and 'dragstop'.
     */
    class DragObserver {
        constructor(opts) {
            this.start = {
                x: 0,
                y: 0,
                altKey: false,
                ctrlKey: false,
                metaKey: false,
                shiftKey: false,
            };
            this.dragElem = null;
            this.dragging = false;
            // TODO: touch events
            this.events = ["mousedown", "mouseup", "mousemove", "keydown"];
            if (!opts.root) {
                throw new Error("Missing `root` option.");
            }
            this.opts = Object.assign({ thresh: 5 }, opts);
            this.root = opts.root;
            this._handler = this.handleEvent.bind(this);
            this.events.forEach((type) => {
                this.root.addEventListener(type, this._handler);
            });
        }
        /** Unregister all event listeners. */
        disconnect() {
            this.events.forEach((type) => {
                this.root.removeEventListener(type, this._handler);
            });
        }
        getDragElem() {
            return this.dragElem;
        }
        isDragging() {
            return this.dragging;
        }
        stopDrag(cb_event) {
            if (this.dragging && this.opts.dragstop && cb_event) {
                cb_event.type = "dragstop";
                this.opts.dragstop(cb_event);
            }
            this.dragElem = null;
            this.dragging = false;
        }
        handleEvent(e) {
            const type = e.type;
            const opts = this.opts;
            const cb_event = {
                type: e.type,
                event: e,
                dragElem: this.dragElem,
                dx: e.pageX - this.start.x,
                dy: e.pageY - this.start.y,
                apply: undefined,
            };
            switch (type) {
                case "keydown":
                    this.stopDrag(cb_event);
                    break;
                case "mousedown":
                    if (this.dragElem) {
                        this.stopDrag(cb_event);
                        break;
                    }
                    if (opts.selector) {
                        let elem = e.target;
                        if (elem.matches(opts.selector)) {
                            this.dragElem = elem;
                        }
                        else {
                            elem = elem.closest(opts.selector);
                            if (elem) {
                                this.dragElem = elem;
                            }
                            else {
                                break; // no event delegation selector matched
                            }
                        }
                    }
                    this.start.x = e.pageX;
                    this.start.y = e.pageY;
                    this.start.altKey = e.altKey;
                    this.start.ctrlKey = e.ctrlKey;
                    this.start.metaKey = e.metaKey;
                    this.start.shiftKey = e.shiftKey;
                    break;
                case "mousemove":
                    // TODO: debounce/throttle?
                    // TODO: horizontal mode: ignore if dx unchanged
                    if (!this.dragElem) {
                        break;
                    }
                    if (!this.dragging) {
                        if (opts.thresh) {
                            const dist2 = cb_event.dx * cb_event.dx + cb_event.dy * cb_event.dy;
                            if (dist2 < opts.thresh * opts.thresh) {
                                break;
                            }
                        }
                        cb_event.type = "dragstart";
                        if (opts.dragstart(cb_event) === false) {
                            this.stopDrag(cb_event);
                            break;
                        }
                        this.dragging = true;
                    }
                    if (this.dragging && this.opts.drag) {
                        cb_event.type = "drag";
                        this.opts.drag(cb_event);
                    }
                    break;
                case "mouseup":
                    if (!this.dragging) {
                        this.stopDrag(cb_event);
                        break;
                    }
                    if (e.button === 0) {
                        cb_event.apply = true;
                    }
                    else {
                        cb_event.apply = false;
                    }
                    this.stopDrag(cb_event);
                    break;
            }
        }
    }

    /*!
     * Wunderbaum - ext-grid
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    class GridExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "grid", {
            // throttle: 200,
            });
            this.observer = new DragObserver({
                root: window.document,
                selector: "span.wb-col-resizer",
                thresh: 4,
                // throttle: 400,
                dragstart: (e) => {
                    return this.tree.element.contains(e.dragElem);
                },
                drag: (e) => {
                    // TODO: throttle
                    return this.handleDrag(e);
                },
                dragstop: (e) => {
                    return this.handleDrag(e);
                },
            });
        }
        init() {
            super.init();
        }
        handleDrag(e) {
            const info = Wunderbaum.getEventInfo(e.event);
            // this.tree.options.
            this.tree.log(`${e.type}(${e.dx})`, e, info);
        }
    }

    /*!
     * Wunderbaum - deferred
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    /**
     * Implement a ES6 Promise, that exposes a resolve() and reject() method.
     *
     * Loosely mimics {@link https://api.jquery.com/category/deferred-object/ | jQuery.Deferred}.
     * Example:
     * ```js
     * function foo() {
     *   let dfd = new Deferred(),
     *   ...
     *   dfd.resolve('foo')
     *   ...
     *   return dfd.promise();
     * }
     * ```
     */
    class Deferred {
        constructor() {
            this._promise = new Promise((resolve, reject) => {
                this._resolve = resolve;
                this._reject = reject;
            });
        }
        /** Resolve the Promise. */
        resolve(value) {
            this._resolve(value);
        }
        /** Reject the Promise. */
        reject(reason) {
            this._reject(reason);
        }
        /** Return the native Promise instance.*/
        promise() {
            return this._promise;
        }
        /** Call Promise.then on the embedded promise instance.*/
        then(cb) {
            return this._promise.then(cb);
        }
        /** Call Promise.catch on the embedded promise instance.*/
        catch(cb) {
            return this._promise.catch(cb);
        }
        /** Call Promise.finally on the embedded promise instance.*/
        finally(cb) {
            return this._promise.finally(cb);
        }
    }

    /*!
     * Wunderbaum - wunderbaum_node
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    /** WunderbaumNode properties that can be passed with source data.
     * (Any other source properties will be stored as `node.data.PROP`.)
     */
    const NODE_PROPS = new Set([
        "checkbox",
        "classes",
        "expanded",
        "icon",
        "iconTooltip",
        "key",
        "lazy",
        "_partsel",
        "radiogroup",
        "refKey",
        "selected",
        "statusNodeType",
        "title",
        "tooltip",
        "type",
        "unselectable",
    ]);
    /** WunderbaumNode properties that will be returned by `node.toDict()`.)
     */
    const NODE_DICT_PROPS = new Set(NODE_PROPS);
    NODE_DICT_PROPS.delete("_partsel");
    NODE_DICT_PROPS.delete("unselectable");
    /**
     * A single tree node.
     *
     * **NOTE:** <br>
     * Generally you should not modify properties directly, since this may break
     * the internal bookkeeping.
     */
    class WunderbaumNode {
        constructor(tree, parent, data) {
            var _a, _b;
            /** Reference key. Unlike {@link key}, a `refKey` may occur multiple
             * times within a tree (in this case we have 'clone nodes').
             * @see Use {@link setKey} to modify.
             */
            this.refKey = undefined;
            this.children = null;
            /** Additional classes added to `div.wb-row`.
             * @see {@link hasClass}, {@link setClass}. */
            this.classes = null; //new Set<string>();
            /** Custom data that was passed to the constructor */
            this.data = {};
            this._isLoading = false;
            this._requestId = 0;
            this._errorInfo = null;
            this._partsel = false;
            this._partload = false;
            this.subMatchCount = 0;
            this._rowIdx = 0;
            this._rowElem = undefined;
            assert(!parent || parent.tree === tree, `Invalid parent: ${parent}`);
            assert(!data.children, "'children' not allowed here");
            this.tree = tree;
            this.parent = parent;
            this.key = "" + ((_a = data.key) !== null && _a !== void 0 ? _a : ++WunderbaumNode.sequence);
            this.title = "" + ((_b = data.title) !== null && _b !== void 0 ? _b : "<" + this.key + ">");
            data.refKey != null ? (this.refKey = "" + data.refKey) : 0;
            data.type != null ? (this.type = "" + data.type) : 0;
            this.expanded = data.expanded === true;
            data.icon != null ? (this.icon = data.icon) : 0;
            this.lazy = data.lazy === true;
            data.statusNodeType != null
                ? (this.statusNodeType = ("" + data.statusNodeType))
                : 0;
            data.colspan != null ? (this.colspan = !!data.colspan) : 0;
            // Selection
            data.checkbox != null ? (this.checkbox = !!data.checkbox) : 0;
            data.radiogroup != null ? (this.radiogroup = !!data.radiogroup) : 0;
            this.selected = data.selected === true;
            data.unselectable === true ? (this.unselectable = true) : 0;
            if (data.classes) {
                this.setClass(data.classes);
            }
            // Store custom fields as `node.data`
            for (const [key, value] of Object.entries(data)) {
                if (!NODE_PROPS.has(key)) {
                    this.data[key] = value;
                }
            }
            if (parent && !this.statusNodeType) {
                // Don't register root node or status nodes
                tree._registerNode(this);
            }
        }
        /**
         * Return readable string representation for this instance.
         * @internal
         */
        toString() {
            return `WunderbaumNode@${this.key}<'${this.title}'>`;
        }
        /**
         * Iterate all descendant nodes depth-first, pre-order using `for ... of ...` syntax.
         * More concise, but slightly slower than {@link WunderbaumNode.visit}.
         *
         * Example:
         * ```js
         * for(const n of node) {
         *   ...
         * }
         * ```
         */
        *[Symbol.iterator]() {
            // let node: WunderbaumNode | null = this;
            const cl = this.children;
            if (cl) {
                for (let i = 0, l = cl.length; i < l; i++) {
                    const n = cl[i];
                    yield n;
                    if (n.children) {
                        yield* n;
                    }
                }
                // Slower:
                // for (let node of this.children) {
                //   yield node;
                //   yield* node : 0;
                // }
            }
        }
        // /** Return an option value. */
        // protected _getOpt(
        //   name: string,
        //   nodeObject: any = null,
        //   treeOptions: any = null,
        //   defaultValue: any = null
        // ): any {
        //   return evalOption(
        //     name,
        //     this,
        //     nodeObject || this,
        //     treeOptions || this.tree.options,
        //     defaultValue
        //   );
        // }
        /** Call event handler if defined in tree.options.
         * Example:
         * ```js
         * node._callEvent("edit.beforeEdit", {foo: 42})
         * ```
         */
        _callEvent(type, extra) {
            return this.tree._callEvent(type, extend({
                node: this,
                typeInfo: this.type ? this.tree.types[this.type] : {},
            }, extra));
        }
        /**
         * Append (or insert) a list of child nodes.
         *
         * Tip: pass `{ before: 0 }` to prepend new nodes as first children.
         *
         * @returns first child added
         */
        addChildren(nodeData, options) {
            const tree = this.tree;
            let { before = null, applyMinExpanLevel = true, _level } = options !== null && options !== void 0 ? options : {};
            // let { before, loadLazy=true, _level } = options ?? {};
            // const isTopCall = _level == null;
            _level !== null && _level !== void 0 ? _level : (_level = this.getLevel());
            const nodeList = [];
            try {
                tree.enableUpdate(false);
                if (isPlainObject(nodeData)) {
                    nodeData = [nodeData];
                }
                const forceExpand = applyMinExpanLevel && _level < tree.options.minExpandLevel;
                for (const child of nodeData) {
                    const subChildren = child.children;
                    delete child.children;
                    const n = new WunderbaumNode(tree, this, child);
                    if (forceExpand && !n.isUnloaded()) {
                        n.expanded = true;
                    }
                    nodeList.push(n);
                    if (subChildren) {
                        n.addChildren(subChildren, { _level: _level + 1 });
                    }
                }
                if (!this.children) {
                    this.children = nodeList;
                }
                else if (before == null || this.children.length === 0) {
                    this.children = this.children.concat(nodeList);
                }
                else {
                    // Returns null if before is not a direct child:
                    before = this.findDirectChild(before);
                    const pos = this.children.indexOf(before);
                    assert(pos >= 0, `options.before must be a direct child of ${this}`);
                    // insert nodeList after children[pos]
                    this.children.splice(pos, 0, ...nodeList);
                }
                // this.triggerModifyChild("add", nodeList.length === 1 ? nodeList[0] : null);
                tree.update(ChangeType.structure);
            }
            finally {
                // if (tree.options.selectMode === "hier") {
                //   if (this.parent && this.parent.children) {
                //     this.fixSelection3FromEndNodes();
                //   } else {
                //     // may happen when loading __root__;
                //   }
                // }
                tree.enableUpdate(true);
            }
            // if(isTopCall && loadLazy){
            //   this.logWarn("addChildren(): loadLazy is not yet implemented.")
            // }
            return nodeList[0];
        }
        /**
         * Append or prepend a node, or append a child node.
         *
         * This a convenience function that calls addChildren()
         *
         * @param nodeData node definition
         * @param [mode=child] 'before', 'after', 'firstChild', or 'child' ('over' is a synonym for 'child')
         * @returns new node
         */
        addNode(nodeData, mode = "appendChild") {
            if (mode === "over") {
                mode = "appendChild"; // compatible with drop region
            }
            switch (mode) {
                case "after":
                    return this.parent.addChildren(nodeData, {
                        before: this.getNextSibling(),
                    });
                case "before":
                    return this.parent.addChildren(nodeData, { before: this });
                case "prependChild":
                    // Insert before the first child if any
                    // let insertBefore = this.children ? this.children[0] : undefined;
                    return this.addChildren(nodeData, { before: 0 });
                case "appendChild":
                    return this.addChildren(nodeData);
            }
            assert(false, `Invalid mode: ${mode}`);
            return undefined;
        }
        /**
         * Apply a modification (or navigation) operation.
         *
         * @see {@link Wunderbaum.applyCommand}
         */
        applyCommand(cmd, options) {
            return this.tree.applyCommand(cmd, this, options);
        }
        /**
         * Collapse all expanded sibling nodes if any.
         * (Automatically called when `autoCollapse` is true.)
         */
        collapseSiblings(options) {
            for (const node of this.parent.children) {
                if (node !== this && node.expanded) {
                    node.setExpanded(false, options);
                }
            }
        }
        /**
         * Add/remove one or more classes to `<div class='wb-row'>`.
         *
         * This also maintains `node.classes`, so the class will survive a re-render.
         *
         * @param className one or more class names. Multiple classes can be passed
         *     as space-separated string, array of strings, or set of strings.
         */
        setClass(className, flag = true) {
            const cnSet = toSet(className);
            if (flag) {
                if (this.classes === null) {
                    this.classes = new Set();
                }
                cnSet.forEach((cn) => {
                    var _a;
                    this.classes.add(cn);
                    (_a = this._rowElem) === null || _a === void 0 ? void 0 : _a.classList.toggle(cn, flag);
                });
            }
            else {
                if (this.classes === null) {
                    return;
                }
                cnSet.forEach((cn) => {
                    var _a;
                    this.classes.delete(cn);
                    (_a = this._rowElem) === null || _a === void 0 ? void 0 : _a.classList.toggle(cn, flag);
                });
                if (this.classes.size === 0) {
                    this.classes = null;
                }
            }
        }
        /** Start editing this node's title. */
        startEditTitle() {
            this.tree._callMethod("edit.startEditTitle", this);
        }
        /** Call `setExpanded()` on all descendant nodes. */
        async expandAll(flag = true, options) {
            const tree = this.tree;
            const minExpandLevel = this.tree.options.minExpandLevel;
            const { depth = 99, loadLazy, force, keepActiveNodeVisible = true, } = options !== null && options !== void 0 ? options : {};
            const expandOpts = {
                scrollIntoView: false,
                force: force,
                loadLazy: loadLazy,
            };
            // this.logInfo(`expandAll(${flag})`);
            // Expand all direct children in parallel:
            async function _iter(n, level) {
                var _a;
                // n.logInfo(`  _iter(${level})`);
                if (level === 0) {
                    return;
                }
                // if (!flag && minExpandLevel && !force && n.getLevel() <= minExpandLevel) {
                //   return; // Do not collapse until minExpandLevel
                // }
                const level_1 = level == null ? null : level - 1;
                const promises = [];
                (_a = n.children) === null || _a === void 0 ? void 0 : _a.forEach((cn) => {
                    if (flag) {
                        if (!cn.expanded && (cn.children || (loadLazy && cn.lazy))) {
                            // Node is collapsed and may be expanded (i.e. has children or is lazy)
                            // Expanding may be async, so we store the promise.
                            // Also the recursion is delayed until expansion finished.
                            const p = cn.setExpanded(true, expandOpts);
                            promises.push(p);
                            p.then(async () => {
                                await _iter(cn, level_1);
                            });
                        }
                        else {
                            // We don't expand the node, but still visit descendants.
                            // There we may find lazy nodes, so we
                            promises.push(_iter(cn, level_1));
                        }
                    }
                    else {
                        // Collapsing is always synchronous, so no promises required
                        if (!minExpandLevel || force || cn.getLevel() > minExpandLevel) {
                            // Do not collapse until minExpandLevel
                            cn.setExpanded(false, expandOpts);
                        }
                        _iter(cn, level_1); // recursion, even if cn was already collapsed
                    }
                });
                return new Promise((resolve) => {
                    Promise.all(promises).then(() => {
                        resolve(true);
                    });
                });
            }
            const tag = tree.logTime(`${this}.expandAll(${flag})`);
            try {
                tree.enableUpdate(false);
                await _iter(this, depth);
            }
            finally {
                tree.enableUpdate(true);
                tree.logTimeEnd(tag);
            }
            if (tree.activeNode && keepActiveNodeVisible) {
                tree.activeNode.scrollIntoView();
            }
        }
        /**
         * Find all descendant nodes that match condition (excluding self).
         *
         * If `match` is a string, search for exact node title.
         * If `match` is a RegExp expression, apply it to node.title, using
         * [RegExp.test()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test).
         * If `match` is a callback, match all nodes for that the callback(node) returns true.
         *
         * Returns an empty array if no nodes were found.
         *
         * Examples:
         * ```js
         * // Match all node titles that match exactly 'Joe':
         * nodeList = node.findAll("Joe")
         * // Match all node titles that start with 'Joe' case sensitive:
         * nodeList = node.findAll(/^Joe/)
         * // Match all node titles that contain 'oe', case insensitive:
         * nodeList = node.findAll(/oe/i)
         * // Match all nodes with `data.price` >= 99:
         * nodeList = node.findAll((n) => {
         *   return n.data.price >= 99;
         * })
         * ```
         */
        findAll(match) {
            const matcher = typeof match === "function" ? match : makeNodeTitleMatcher(match);
            const res = [];
            this.visit((n) => {
                if (matcher(n)) {
                    res.push(n);
                }
            });
            return res;
        }
        /** Return the direct child with a given key, index or null. */
        findDirectChild(ptr) {
            const cl = this.children;
            if (!cl) {
                return null;
            }
            if (typeof ptr === "string") {
                for (let i = 0, l = cl.length; i < l; i++) {
                    if (cl[i].key === ptr) {
                        return cl[i];
                    }
                }
            }
            else if (typeof ptr === "number") {
                return cl[ptr];
            }
            else if (ptr.parent === this) {
                // Return null if `ptr` is not a direct child
                return ptr;
            }
            return null;
        }
        /**
         * Find first descendant node that matches condition (excluding self) or null.
         *
         * @see {@link WunderbaumNode.findAll} for examples.
         */
        findFirst(match) {
            const matcher = typeof match === "function" ? match : makeNodeTitleMatcher(match);
            let res = null;
            this.visit((n) => {
                if (matcher(n)) {
                    res = n;
                    return false;
                }
            });
            return res;
        }
        /** Find a node relative to self.
         *
         * @see {@link Wunderbaum.findRelatedNode|tree.findRelatedNode()}
         */
        findRelatedNode(where, includeHidden = false) {
            return this.tree.findRelatedNode(this, where, includeHidden);
        }
        /**
         * Iterator version of {@link WunderbaumNode.format}.
         */
        *format_iter(name_cb, connectors) {
            connectors !== null && connectors !== void 0 ? connectors : (connectors = ["    ", " |  ", " ╰─ ", " ├─ "]);
            name_cb !== null && name_cb !== void 0 ? name_cb : (name_cb = (node) => "" + node);
            function _is_last(node) {
                const ca = node.parent.children;
                return node === ca[ca.length - 1];
            }
            const _format_line = (node) => {
                // https://www.measurethat.net/Benchmarks/Show/12196/0/arr-unshift-vs-push-reverse-small-array
                const parts = [name_cb(node)];
                parts.unshift(connectors[_is_last(node) ? 2 : 3]);
                let p = node.parent;
                while (p && p !== this) {
                    // `this` is the top node
                    parts.unshift(connectors[_is_last(p) ? 0 : 1]);
                    p = p.parent;
                }
                return parts.join("");
            };
            yield name_cb(this);
            for (const node of this) {
                yield _format_line(node);
            }
        }
        /**
         * Return a multiline string representation of a node/subnode hierarchy.
         * Mostly useful for debugging.
         *
         * Example:
         * ```js
         * console.info(tree.getActiveNode().format((n)=>n.title));
         * ```
         * logs
         * ```
         * Books
         *  ├─ Art of War
         *  ╰─ Don Quixote
         * ```
         * @see {@link WunderbaumNode.format_iter}
         */
        format(name_cb, connectors) {
            const a = [];
            for (const line of this.format_iter(name_cb, connectors)) {
                a.push(line);
            }
            return a.join("\n");
        }
        /** Return the `<span class='wb-col'>` element with a given index or id.
         * @returns {WunderbaumNode | null}
         */
        getColElem(colIdx) {
            var _a;
            if (typeof colIdx === "string") {
                colIdx = this.tree.columns.findIndex((value) => value.id === colIdx);
            }
            const colElems = (_a = this._rowElem) === null || _a === void 0 ? void 0 : _a.querySelectorAll("span.wb-col");
            return colElems ? colElems[colIdx] : null;
        }
        /**
         * Return all nodes with the same refKey.
         *
         * @param includeSelf Include this node itself.
         * @see {@link Wunderbaum.findByRefKey}
         */
        getCloneList(includeSelf = false) {
            if (!this.refKey) {
                return [];
            }
            const clones = this.tree.findByRefKey(this.refKey);
            if (includeSelf) {
                return clones;
            }
            return [...clones].filter((n) => n !== this);
        }
        /** Return the first child node or null.
         * @returns {WunderbaumNode | null}
         */
        getFirstChild() {
            return this.children ? this.children[0] : null;
        }
        /** Return the last child node or null.
         * @returns {WunderbaumNode | null}
         */
        getLastChild() {
            return this.children ? this.children[this.children.length - 1] : null;
        }
        /** Return node depth (starting with 1 for top level nodes). */
        getLevel() {
            let i = 0, p = this.parent;
            while (p) {
                i++;
                p = p.parent;
            }
            return i;
        }
        /** Return the successive node (under the same parent) or null. */
        getNextSibling() {
            const ac = this.parent.children;
            const idx = ac.indexOf(this);
            return ac[idx + 1] || null;
        }
        /** Return the parent node (null for the system root node). */
        getParent() {
            // TODO: return null for top-level nodes?
            return this.parent;
        }
        /** Return an array of all parent nodes (top-down).
         * @param includeRoot Include the invisible system root node.
         * @param includeSelf Include the node itself.
         */
        getParentList(includeRoot = false, includeSelf = false) {
            const l = [];
            let dtn = includeSelf ? this : this.parent;
            while (dtn) {
                if (includeRoot || dtn.parent) {
                    l.unshift(dtn);
                }
                dtn = dtn.parent;
            }
            return l;
        }
        /** Return a string representing the hierachical node path, e.g. "a/b/c".
         * @param includeSelf
         * @param node property name or callback
         * @param separator
         */
        getPath(includeSelf = true, part = "title", separator = "/") {
            // includeSelf = includeSelf !== false;
            // part = part || "title";
            // separator = separator || "/";
            let val;
            const path = [];
            const isFunc = typeof part === "function";
            this.visitParents((n) => {
                if (n.parent) {
                    val = isFunc
                        ? part(n)
                        : n[part];
                    path.unshift(val);
                }
                return undefined; // TODO remove this line
            }, includeSelf);
            return path.join(separator);
        }
        /** Return the preceeding node (under the same parent) or null. */
        getPrevSibling() {
            const ac = this.parent.children;
            const idx = ac.indexOf(this);
            return ac[idx - 1] || null;
        }
        /** Return true if node has children.
         * Return undefined if not sure, i.e. the node is lazy and not yet loaded.
         */
        hasChildren() {
            if (this.lazy) {
                if (this.children == null) {
                    return undefined; // null or undefined: Not yet loaded
                }
                else if (this.children.length === 0) {
                    return false; // Loaded, but response was empty
                }
                else if (this.children.length === 1 &&
                    this.children[0].isStatusNode()) {
                    return undefined; // Currently loading or load error
                }
                return true; // One or more child nodes
            }
            return !!(this.children && this.children.length);
        }
        /** Return true if node has className set. */
        hasClass(className) {
            return this.classes ? this.classes.has(className) : false;
        }
        /** Return true if this node is the currently active tree node. */
        isActive() {
            return this.tree.activeNode === this;
        }
        /** Return true if this node is a direct or indirect parent of `other`.
         * @see {@link WunderbaumNode.isParentOf}
         */
        isAncestorOf(other) {
            return other && other.isDescendantOf(this);
        }
        /** Return true if this node is a **direct** subnode of `other`.
         * @see {@link WunderbaumNode.isDescendantOf}
         */
        isChildOf(other) {
            return other && this.parent === other;
        }
        /** Return true if this node's refKey is used by at least one other node.
         */
        isClone() {
            return !!this.refKey && this.tree.findByRefKey(this.refKey).length > 1;
        }
        /** Return true if this node's title spans all columns, i.e. the node has no
         * grid cells.
         */
        isColspan() {
            return !!this.getOption("colspan");
        }
        /** Return true if this node is a direct or indirect subnode of `other`.
         * @see {@link WunderbaumNode.isChildOf}
         */
        isDescendantOf(other) {
            if (!other || other.tree !== this.tree) {
                return false;
            }
            let p = this.parent;
            while (p) {
                if (p === other) {
                    return true;
                }
                if (p === p.parent) {
                    error(`Recursive parent link: ${p}`);
                }
                p = p.parent;
            }
            return false;
        }
        /** Return true if this node has children, i.e. the node is generally expandable.
         * If `andCollapsed` is set, we also check if this node is collapsed, i.e.
         * an expand operation is currently possible.
         */
        isExpandable(andCollapsed = false) {
            // `false` is never expandable (unoffical)
            if ((andCollapsed && this.expanded) || this.children === false) {
                return false;
            }
            if (this.children == null) {
                return !!this.lazy; // null or undefined can trigger lazy load
            }
            if (this.children.length === 0) {
                return !!this.tree.options.emptyChildListExpandable;
            }
            return true;
        }
        /** Return true if _this_ node is currently in edit-title mode.
         *
         * See {@link Wunderbaum.startEditTitle} to check if any node is currently edited.
         */
        isEditingTitle() {
            return this.tree._callMethod("edit.isEditingTitle", this);
        }
        /** Return true if this node is currently expanded. */
        isExpanded() {
            return !!this.expanded;
        }
        /** Return true if this node is the first node of its parent's children. */
        isFirstSibling() {
            const p = this.parent;
            return !p || p.children[0] === this;
        }
        /** Return true if this node is the last node of its parent's children. */
        isLastSibling() {
            const p = this.parent;
            return !p || p.children[p.children.length - 1] === this;
        }
        /** Return true if this node is lazy (even if data was already loaded) */
        isLazy() {
            return !!this.lazy;
        }
        /** Return true if node is lazy and loaded. For non-lazy nodes always return true. */
        isLoaded() {
            return !this.lazy || this.hasChildren() !== undefined; // Also checks if the only child is a status node
        }
        /** Return true if node is currently loading, i.e. a GET request is pending. */
        isLoading() {
            return this._isLoading;
        }
        /** Return true if this node is a temporarily generated status node of type 'paging'. */
        isPagingNode() {
            return this.statusNodeType === "paging";
        }
        /** Return true if this node is a **direct** parent of `other`.
         * @see {@link WunderbaumNode.isAncestorOf}
         */
        isParentOf(other) {
            return other && other.parent === this;
        }
        /** (experimental) Return true if this node is partially loaded. */
        isPartload() {
            return !!this._partload;
        }
        /** Return true if this node is partially selected (tri-state). */
        isPartsel() {
            return !this.selected && !!this._partsel;
        }
        /** Return true if this node has DOM representaion, i.e. is displayed in the viewport. */
        isRadio() {
            return !!this.parent.radiogroup || this.getOption("checkbox") === "radio";
        }
        /** Return true if this node has DOM representaion, i.e. is displayed in the viewport. */
        isRendered() {
            return !!this._rowElem;
        }
        /** Return true if this node is the (invisible) system root node.
         * @see {@link WunderbaumNode.isTopLevel}
         */
        isRootNode() {
            return this.tree.root === this;
        }
        /** Return true if this node is selected, i.e. the checkbox is set.
         * `undefined` if partly selected (tri-state), false otherwise.
         */
        isSelected() {
            return this.selected ? true : this._partsel ? undefined : false;
        }
        /** Return true if this node is a temporarily generated system node like
         * 'loading', 'paging', or 'error' (node.statusNodeType contains the type).
         */
        isStatusNode() {
            return !!this.statusNodeType;
        }
        /** Return true if this a top level node, i.e. a direct child of the (invisible) system root node. */
        isTopLevel() {
            return this.tree.root === this.parent;
        }
        /** Return true if node is marked lazy but not yet loaded.
         * For non-lazy nodes always return false.
         */
        isUnloaded() {
            // Also checks if the only child is a status node:
            return this.hasChildren() === undefined;
        }
        /** Return true if all parent nodes are expanded. Note: this does not check
         * whether the node is scrolled into the visible part of the screen or viewport.
         */
        isVisible() {
            const hasFilter = this.tree.filterMode === "hide";
            const parents = this.getParentList(false, false);
            // TODO: check $(n.span).is(":visible")
            // i.e. return false for nodes (but not parents) that are hidden
            // by a filter
            if (hasFilter && !this.match && !this.subMatchCount) {
                // this.debug( "isVisible: HIDDEN (" + hasFilter + ", " + this.match + ", " + this.match + ")" );
                return false;
            }
            for (let i = 0, l = parents.length; i < l; i++) {
                const n = parents[i];
                if (!n.expanded) {
                    // this.debug("isVisible: HIDDEN (parent collapsed)");
                    return false;
                }
                // if (hasFilter && !n.match && !n.subMatchCount) {
                // 	this.debug("isVisible: HIDDEN (" + hasFilter + ", " + this.match + ", " + this.match + ")");
                // 	return false;
                // }
            }
            // this.debug("isVisible: VISIBLE");
            return true;
        }
        _loadSourceObject(source, level) {
            var _a;
            const tree = this.tree;
            level !== null && level !== void 0 ? level : (level = this.getLevel());
            // Let caller modify the parsed JSON response:
            const res = this._callEvent("receive", { response: source });
            if (res != null) {
                source = res;
            }
            if (isArray(source)) {
                source = { children: source };
            }
            assert(isPlainObject(source), `Expected an array or plain object: ${source}`);
            const format = (_a = source.format) !== null && _a !== void 0 ? _a : "nested";
            assert(format === "nested" || format === "flat", `Expected source.format = 'nested' or 'flat': ${format}`);
            // Pre-rocess for 'nested' or 'flat' format
            decompressSourceData(source);
            assert(source.children, "If `source` is an object, it must have a `children` property");
            if (source.types) {
                tree.logInfo("Redefine types", source.columns);
                tree.setTypes(source.types, false);
                delete source.types;
            }
            if (source.columns) {
                tree.logInfo("Redefine columns", source.columns);
                tree.columns = source.columns;
                delete source.columns;
                tree.update(ChangeType.colStructure);
            }
            this.addChildren(source.children);
            // Add extra data to `tree.data`
            for (const [key, value] of Object.entries(source)) {
                if (!RESERVED_TREE_SOURCE_KEYS.has(key)) {
                    tree.data[key] = value;
                    // tree.logDebug(`Add source.${key} to tree.data.${key}`);
                }
            }
            if (tree.options.selectMode === "hier") {
                this.fixSelection3FromEndNodes();
            }
            this._callEvent("load");
        }
        async _fetchWithOptions(source) {
            var _a, _b;
            // Either a URL string or an object with a `.url` property.
            let url, params, body, options, rest;
            let fetchOpts = {};
            if (typeof source === "string") {
                // source is a plain URL string: assume GET request
                url = source;
                fetchOpts.method = "GET";
            }
            else if (isPlainObject(source)) {
                // source is a plain object with `.url` property.
                ({ url, params, body, options, ...rest } = source);
                assert(!rest || Object.keys(rest).length === 0, `Unexpected source properties: ${Object.keys(rest)}. Use 'options' instead.`);
                assert(typeof url === "string", `expected source.url as string`);
                if (isPlainObject(options)) {
                    fetchOpts = options;
                }
                if (isPlainObject(body)) {
                    // we also accept 'body' as object...
                    assert(!fetchOpts.body, "options.body should be passed as source.body");
                    fetchOpts.body = JSON.stringify(fetchOpts.body);
                    (_a = fetchOpts.method) !== null && _a !== void 0 ? _a : (fetchOpts.method = "POST"); // set default
                }
                if (isPlainObject(params)) {
                    url += "?" + new URLSearchParams(params);
                    (_b = fetchOpts.method) !== null && _b !== void 0 ? _b : (fetchOpts.method = "GET"); // set default
                }
            }
            else {
                url = ""; // keep linter happy
                error(`Unsupported source format: ${source}`);
            }
            this.setStatus(NodeStatusType.loading);
            const response = await fetch(url, fetchOpts);
            if (!response.ok) {
                error(`GET ${url} returned ${response.status}, ${response}`);
            }
            return await response.json();
        }
        /** Download  data from the cloud, then call `.update()`. */
        async load(source) {
            const tree = this.tree;
            const requestId = Date.now();
            const prevParent = this.parent;
            const start = Date.now();
            let elap = 0, elapLoad = 0, elapProcess = 0;
            // Check for overlapping requests
            if (this._requestId) {
                this.logWarn(`Recursive load request #${requestId} while #${this._requestId} is pending.`);
                // 	node.debug("Send load request #" + requestId);
            }
            this._requestId = requestId;
            // const timerLabel = tree.logTime(this + ".load()");
            try {
                const url = typeof source === "string" ? source : source.url;
                if (!url) {
                    // An array or a plain object (that does NOT contain a `.url` property)
                    // will be treated as native Wunderbaum data
                    if (typeof source.then === "function") {
                        const msg = tree.logTime(`Resolve thenable ${source}`);
                        source = await Promise.resolve(source);
                        tree.logTimeEnd(msg);
                    }
                    this._loadSourceObject(source);
                    elapProcess = Date.now() - start;
                }
                else {
                    // Either a URL string or an object with a `.url` property.
                    const data = await this._fetchWithOptions(source);
                    elapLoad = Date.now() - start;
                    if (this._requestId && this._requestId > requestId) {
                        this.logWarn(`Ignored load response #${requestId} because #${this._requestId} is pending.`);
                        return;
                    }
                    else {
                        this.logDebug(`Received response for load request #${requestId}`);
                    }
                    if (this.parent === null && prevParent !== null) {
                        this.logWarn("Lazy parent node was removed while loading: discarding response.");
                        return;
                    }
                    this.setStatus(NodeStatusType.ok);
                    // if (data.columns) {
                    //   tree.logInfo("Re-define columns", data.columns);
                    //   util.assert(!this.parent);
                    //   tree.columns = data.columns;
                    //   delete data.columns;
                    //   tree.updateColumns({ calculateCols: false });
                    // }
                    const startProcess = Date.now();
                    this._loadSourceObject(data);
                    elapProcess = Date.now() - startProcess;
                }
            }
            catch (error) {
                this.logError("Error during load()", source, error);
                this._callEvent("error", { error: error });
                this.setStatus(NodeStatusType.error, { message: "" + error });
                throw error;
            }
            finally {
                this._requestId = 0;
                elap = Date.now() - start;
                if (tree.options.debugLevel >= 3) {
                    tree.logInfo(`Load source took ${elap / 1000} seconds ` +
                        `(transfer: ${elapLoad / 1000}s, ` +
                        `processing: ${elapProcess / 1000}s)`);
                }
            }
        }
        /**
         * Load content of a lazy node.
         * If the node is already loaded, nothing happens.
         * @param [forceReload=false] If true, reload even if already loaded.
         */
        async loadLazy(forceReload = false) {
            const wasExpanded = this.expanded;
            assert(this.lazy, "load() requires a lazy node");
            if (!forceReload && !this.isUnloaded()) {
                return; // Already loaded: nothing to do
            }
            if (this.isLoading()) {
                this.logWarn("loadLazy() called while already loading: ignored.");
                return; // Already loading: prevent duplicate requests
            }
            if (this.isLoaded()) {
                this.resetLazy(); // Also collapses if currently expanded
            }
            // `lazyLoad` may be long-running, so mark node as loading now. `this.load()`
            // will reset the status later.
            this.setStatus(NodeStatusType.loading);
            try {
                const source = await this._callEvent("lazyLoad");
                if (source === false) {
                    this.setStatus(NodeStatusType.ok);
                    return;
                }
                assert(isArray(source) || (source && source.url), "The lazyLoad event must return a node list, `{url: ...}`, or false.");
                await this.load(source);
                this.setStatus(NodeStatusType.ok); // Also resets `this._isLoading`
                if (wasExpanded) {
                    this.expanded = true;
                    this.tree.update(ChangeType.structure);
                }
                else {
                    this.update(); // Fix expander icon to 'loaded'
                }
            }
            catch (e) {
                this.logError("Error during loadLazy()", e);
                this._callEvent("error", { error: e });
                // Also resets `this._isLoading`:
                this.setStatus(NodeStatusType.error, { message: "" + e });
            }
            return;
        }
        /** Write to `console.log` with node name as prefix if opts.debugLevel >= 4.
         * @see {@link WunderbaumNode.logDebug}
         */
        log(...args) {
            if (this.tree.options.debugLevel >= 4) {
                console.log(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.debug` with node name as prefix if opts.debugLevel >= 4
         * and browser console level includes debug/verbose messages.
         * @see {@link WunderbaumNode.log}
         */
        logDebug(...args) {
            if (this.tree.options.debugLevel >= 4) {
                console.debug(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.error` with node name as prefix if opts.debugLevel >= 1. */
        logError(...args) {
            if (this.tree.options.debugLevel >= 1) {
                console.error(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.info` with node name as prefix if opts.debugLevel >= 3. */
        logInfo(...args) {
            if (this.tree.options.debugLevel >= 3) {
                console.info(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.warn` with node name as prefix if opts.debugLevel >= 2. */
        logWarn(...args) {
            if (this.tree.options.debugLevel >= 2) {
                console.warn(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Expand all parents and optionally scroll into visible area as neccessary.
         * Promise is resolved, when lazy loading and animations are done.
         * @param {object} [options] passed to `setExpanded()`.
         *     Defaults to {noAnimation: false, noEvents: false, scrollIntoView: true}
         */
        async makeVisible(options) {
            let i;
            const dfd = new Deferred();
            const deferreds = [];
            const parents = this.getParentList(false, false);
            const len = parents.length;
            const noAnimation = getOption(options, "noAnimation", false);
            const scroll = getOption(options, "scrollIntoView", true);
            // Expand bottom-up, so only the top node is animated
            for (i = len - 1; i >= 0; i--) {
                // self.debug("pushexpand" + parents[i]);
                const seOpts = { noAnimation: noAnimation };
                deferreds.push(parents[i].setExpanded(true, seOpts));
            }
            Promise.all(deferreds).then(() => {
                // All expands have finished
                // self.debug("expand DONE", scroll);
                // Note: this.tree may be none when switching demo trees
                if (scroll && this.tree) {
                    // Make sure markup and _rowIdx is updated before we do the scroll calculations
                    this.tree.updatePendingModifications();
                    this.scrollIntoView().then(() => {
                        // self.debug("scroll DONE");
                        dfd.resolve();
                    });
                }
                else {
                    dfd.resolve();
                }
            });
            return dfd.promise();
        }
        /** Move this node to targetNode. */
        moveTo(targetNode, mode = "appendChild", map) {
            if (mode === "over") {
                mode = "appendChild"; // compatible with drop region
            }
            if (mode === "prependChild") {
                if (targetNode.children && targetNode.children.length) {
                    mode = "before";
                    targetNode = targetNode.children[0];
                }
                else {
                    mode = "appendChild";
                }
            }
            let pos;
            const tree = this.tree;
            const prevParent = this.parent;
            const targetParent = mode === "appendChild" ? targetNode : targetNode.parent;
            if (this === targetNode) {
                return;
            }
            else if (!this.parent) {
                error("Cannot move system root");
            }
            else if (targetParent.isDescendantOf(this)) {
                error("Cannot move a node to its own descendant");
            }
            if (targetParent !== prevParent) {
                prevParent.triggerModifyChild("remove", this);
            }
            // Unlink this node from current parent
            if (this.parent.children.length === 1) {
                if (this.parent === targetParent) {
                    return; // #258
                }
                this.parent.children = this.parent.lazy ? [] : null;
                this.parent.expanded = false;
            }
            else {
                pos = this.parent.children.indexOf(this);
                assert(pos >= 0, "invalid source parent");
                this.parent.children.splice(pos, 1);
            }
            // Insert this node to target parent's child list
            this.parent = targetParent;
            if (targetParent.hasChildren()) {
                switch (mode) {
                    case "appendChild":
                        // Append to existing target children
                        targetParent.children.push(this);
                        break;
                    case "before":
                        // Insert this node before target node
                        pos = targetParent.children.indexOf(targetNode);
                        assert(pos >= 0, "invalid target parent");
                        targetParent.children.splice(pos, 0, this);
                        break;
                    case "after":
                        // Insert this node after target node
                        pos = targetParent.children.indexOf(targetNode);
                        assert(pos >= 0, "invalid target parent");
                        targetParent.children.splice(pos + 1, 0, this);
                        break;
                    default:
                        error(`Invalid mode '${mode}'.`);
                }
            }
            else {
                targetParent.children = [this];
            }
            // Let caller modify the nodes
            if (map) {
                targetNode.visit(map, true);
            }
            if (targetParent === prevParent) {
                targetParent.triggerModifyChild("move", this);
            }
            else {
                // prevParent.triggerModifyChild("remove", this);
                targetParent.triggerModifyChild("add", this);
            }
            // Handle cross-tree moves
            if (tree !== targetNode.tree) {
                // Fix node.tree for all source nodes
                // 	util.assert(false, "Cross-tree move is not yet implemented.");
                this.logWarn("Cross-tree moveTo is experimental!");
                this.visit((n) => {
                    // TODO: fix selection state and activation, ...
                    n.tree = targetNode.tree;
                }, true);
            }
            // Make sure we update async, because discarding the markup would prevent
            // DragAndDrop to generate a dragend event on the source node
            setTimeout(() => {
                // Even indentation may have changed:
                tree.update(ChangeType.any);
            }, 0);
            // TODO: fix selection state
            // TODO: fix active state
        }
        /** Set focus relative to this node and optionally activate.
         *
         * 'left' collapses the node if it is expanded, or move to the parent
         * otherwise.
         * 'right' expands the node if it is collapsed, or move to the first
         * child otherwise.
         *
         * @param where 'down', 'first', 'last', 'left', 'parent', 'right', or 'up'.
         *   (Alternatively the `event.key` that would normally trigger this move,
         *   e.g. `ArrowLeft` = 'left'.
         * @param options
         */
        async navigate(where, options) {
            // Allow to pass 'ArrowLeft' instead of 'left'
            where = KEY_TO_ACTION_DICT[where] || where;
            // Otherwise activate or focus the related node
            const node = this.findRelatedNode(where);
            if (!node) {
                this.logWarn(`Could not find related node '${where}'.`);
                return Promise.resolve(this);
            }
            // setFocus/setActive will scroll later (if autoScroll is specified)
            try {
                node.makeVisible({ scrollIntoView: false });
            }
            catch (e) {
                // ignore
            }
            node.setFocus();
            if ((options === null || options === void 0 ? void 0 : options.activate) === false) {
                return Promise.resolve(this);
            }
            return node.setActive(true, { event: options === null || options === void 0 ? void 0 : options.event });
        }
        /** Delete this node and all descendants. */
        remove() {
            const tree = this.tree;
            const pos = this.parent.children.indexOf(this);
            this.triggerModify("remove");
            this.parent.children.splice(pos, 1);
            this.visit((n) => {
                n.removeMarkup();
                tree._unregisterNode(n);
            }, true);
            tree.update(ChangeType.structure);
        }
        /** Remove all descendants of this node. */
        removeChildren() {
            var _a, _b;
            const tree = this.tree;
            if (!this.children) {
                return;
            }
            if ((_a = tree.activeNode) === null || _a === void 0 ? void 0 : _a.isDescendantOf(this)) {
                tree.activeNode.setActive(false); // TODO: don't fire events
            }
            if ((_b = tree.focusNode) === null || _b === void 0 ? void 0 : _b.isDescendantOf(this)) {
                tree._setFocusNode(null);
            }
            // TODO: persist must take care to clear select and expand cookies
            // Unlink children to support GC
            // TODO: also delete this.children (not possible using visit())
            this.triggerModifyChild("remove", null);
            this.visit((n) => {
                tree._unregisterNode(n);
            });
            if (this.lazy) {
                // 'undefined' would be interpreted as 'not yet loaded' for lazy nodes
                this.children = [];
            }
            else {
                this.children = null;
            }
            // util.assert(this.parent); // don't call this for root node
            if (!this.isRootNode()) {
                this.expanded = false;
            }
            this.tree.update(ChangeType.structure);
        }
        /** Remove all HTML markup from the DOM. */
        removeMarkup() {
            if (this._rowElem) {
                delete this._rowElem._wb_node;
                this._rowElem.remove();
                this._rowElem = undefined;
            }
        }
        _getRenderInfo() {
            const allColInfosById = {};
            const renderColInfosById = {};
            const isColspan = this.isColspan();
            const colElems = this._rowElem
                ? (this._rowElem.querySelectorAll("span.wb-col"))
                : null;
            let idx = 0;
            for (const col of this.tree.columns) {
                allColInfosById[col.id] = {
                    id: col.id,
                    idx: idx,
                    elem: colElems ? colElems[idx] : null,
                    info: col,
                };
                // renderColInfosById only contains columns that need rendering:
                if (!isColspan && col.id !== "*") {
                    renderColInfosById[col.id] = allColInfosById[col.id];
                }
                idx++;
            }
            return {
                allColInfosById: allColInfosById,
                renderColInfosById: renderColInfosById,
            };
        }
        _createIcon(iconMap, parentElem, replaceChild, showLoading) {
            let iconSpan;
            let icon = this.getOption("icon");
            if (this._errorInfo) {
                icon = iconMap.error;
            }
            else if (this._isLoading && showLoading) {
                // Status nodes, or nodes without expander (< minExpandLevel) should
                // display the 'loading' status with the i.wb-icon span
                icon = iconMap.loading;
            }
            if (icon === false) {
                return null; // explicitly disabled: don't try default icons
            }
            if (typeof icon === "string") ;
            else if (this.statusNodeType) {
                icon = iconMap[this.statusNodeType];
            }
            else if (this.expanded) {
                icon = iconMap.folderOpen;
            }
            else if (this.children) {
                icon = iconMap.folder;
            }
            else if (this.lazy) {
                icon = iconMap.folderLazy;
            }
            else {
                icon = iconMap.doc;
            }
            // this.log("_createIcon: " + icon);
            if (!icon) {
                iconSpan = document.createElement("i");
                iconSpan.className = "wb-icon";
            }
            else if (icon.indexOf("<") >= 0) {
                // HTML
                iconSpan = elemFromHtml(icon);
            }
            else if (TEST_IMG.test(icon)) {
                // Image URL
                iconSpan = elemFromHtml(`<i class="wb-icon" style="background-image: url('${icon}');">`);
            }
            else {
                // Class name
                iconSpan = document.createElement("i");
                iconSpan.className = "wb-icon " + icon;
            }
            if (replaceChild) {
                parentElem.replaceChild(iconSpan, replaceChild);
            }
            else {
                parentElem.appendChild(iconSpan);
            }
            // Event handler `tree.iconBadge` can return a badge text or HTMLSpanElement
            const cbRes = this._callEvent("iconBadge", { iconSpan: iconSpan });
            let badge = null;
            if (cbRes != null && cbRes !== false) {
                let classes = "";
                let tooltip = "";
                if (isPlainObject(cbRes)) {
                    badge = "" + cbRes.badge;
                    classes = cbRes.badgeClass ? " " + cbRes.badgeClass : "";
                    tooltip = cbRes.badgeTooltip ? ` title="${cbRes.badgeTooltip}"` : "";
                }
                else if (typeof cbRes === "number") {
                    badge = "" + cbRes;
                }
                else {
                    badge = cbRes; // string or HTMLSpanElement
                }
                if (typeof badge === "string") {
                    badge = elemFromHtml(`<span class="wb-badge${classes}"${tooltip}>${escapeHtml(badge)}</span>`);
                }
                if (badge) {
                    iconSpan.append(badge);
                }
            }
            // this.log("_createIcon: ", iconSpan);
            return iconSpan;
        }
        /**
         * Create a whole new `<div class="wb-row">` element.
         * @see {@link WunderbaumNode._render}
         */
        _render_markup(opts) {
            const tree = this.tree;
            const treeOptions = tree.options;
            const checkbox = this.getOption("checkbox");
            const columns = tree.columns;
            const level = this.getLevel();
            const activeColIdx = tree.isRowNav() ? null : tree.activeColIdx;
            let elem;
            let rowDiv = this._rowElem;
            let checkboxSpan = null;
            let expanderSpan = null;
            const isNew = !rowDiv;
            assert(isNew, "Expected unrendered node");
            assert(!isNew || (opts && opts.after), "opts.after expected, unless updating");
            assert(!this.isRootNode(), "Root node not allowed");
            rowDiv = document.createElement("div");
            rowDiv.classList.add("wb-row");
            rowDiv.style.top = this._rowIdx * ROW_HEIGHT + "px";
            this._rowElem = rowDiv;
            // Attach a node reference to the DOM Element:
            rowDiv._wb_node = this;
            const nodeElem = document.createElement("span");
            nodeElem.classList.add("wb-node", "wb-col");
            rowDiv.appendChild(nodeElem);
            let ofsTitlePx = 0;
            if (checkbox) {
                checkboxSpan = document.createElement("i");
                checkboxSpan.classList.add("wb-checkbox");
                if (checkbox === "radio" || this.parent.radiogroup) {
                    checkboxSpan.classList.add("wb-radio");
                }
                nodeElem.appendChild(checkboxSpan);
                ofsTitlePx += ICON_WIDTH;
            }
            for (let i = level - 1; i > 0; i--) {
                elem = document.createElement("i");
                elem.classList.add("wb-indent");
                nodeElem.appendChild(elem);
                ofsTitlePx += ICON_WIDTH;
            }
            if (!treeOptions.minExpandLevel || level > treeOptions.minExpandLevel) {
                expanderSpan = document.createElement("i");
                expanderSpan.classList.add("wb-expander");
                nodeElem.appendChild(expanderSpan);
                ofsTitlePx += ICON_WIDTH;
            }
            // Render the icon (show a 'loading' icon if we do not have an expander that
            // we would prefer).
            const iconSpan = this._createIcon(tree.iconMap, nodeElem, null, !expanderSpan);
            if (iconSpan) {
                ofsTitlePx += ICON_WIDTH;
            }
            const titleSpan = document.createElement("span");
            titleSpan.classList.add("wb-title");
            nodeElem.appendChild(titleSpan);
            // this._callEvent("enhanceTitle", { titleSpan: titleSpan });
            // Store the width of leading icons with the node, so we can calculate
            // the width of the embedded title span later
            nodeElem._ofsTitlePx = ofsTitlePx;
            // Support HTML5 drag-n-drop
            if (tree.options.dnd.dragStart) {
                nodeElem.draggable = true;
            }
            // Render columns
            const isColspan = this.isColspan();
            if (!isColspan && columns.length > 1) {
                let colIdx = 0;
                for (const col of columns) {
                    colIdx++;
                    let colElem;
                    if (col.id === "*") {
                        colElem = nodeElem;
                    }
                    else {
                        colElem = document.createElement("span");
                        colElem.classList.add("wb-col");
                        rowDiv.appendChild(colElem);
                    }
                    if (colIdx === activeColIdx) {
                        colElem.classList.add("wb-active");
                    }
                    // Add classes from `columns` definition to `<div.wb-col>` cells
                    col.classes ? colElem.classList.add(...col.classes.split(" ")) : 0;
                    colElem.style.left = col._ofsPx + "px";
                    colElem.style.width = col._widthPx + "px";
                    if (isNew && col.html) {
                        if (typeof col.html === "string") {
                            colElem.innerHTML = col.html;
                        }
                    }
                }
            }
            // Attach to DOM as late as possible
            const after = opts ? opts.after : "last";
            switch (after) {
                case "first":
                    tree.nodeListElement.prepend(rowDiv);
                    break;
                case "last":
                    tree.nodeListElement.appendChild(rowDiv);
                    break;
                default:
                    opts.after.after(rowDiv);
            }
            // Now go on and fill in data and update classes
            opts.isNew = true;
            this._render_data(opts);
        }
        /**
         * Render `node.title`, `.icon` into an existing row.
         *
         * @see {@link WunderbaumNode._render}
         */
        _render_data(opts) {
            assert(this._rowElem, "No _rowElem");
            const tree = this.tree;
            const treeOptions = tree.options;
            const rowDiv = this._rowElem;
            const isNew = !!opts.isNew; // Called by _render_markup()?
            const preventScroll = !!opts.preventScroll;
            const columns = tree.columns;
            const isColspan = this.isColspan();
            // Row markup already exists
            const nodeElem = rowDiv.querySelector("span.wb-node");
            const titleSpan = nodeElem.querySelector("span.wb-title");
            const scrollTop = tree.element.scrollTop;
            if (this.titleWithHighlight) {
                titleSpan.innerHTML = this.titleWithHighlight;
            }
            else {
                titleSpan.textContent = this.title; // TODO: this triggers scroll events
            }
            // NOTE: At least on Safari, this render call triggers a scroll event
            // probably when a focused input is replaced.
            if (preventScroll) {
                tree.element.scrollTop = scrollTop;
            }
            // Set the width of the title span, so overflow ellipsis work
            if (!treeOptions.skeleton) {
                if (isColspan) {
                    const vpWidth = tree.element.clientWidth;
                    titleSpan.style.width =
                        vpWidth - nodeElem._ofsTitlePx - TITLE_SPAN_PAD_Y + "px";
                }
                else {
                    titleSpan.style.width =
                        columns[0]._widthPx -
                            nodeElem._ofsTitlePx -
                            TITLE_SPAN_PAD_Y +
                            "px";
                }
            }
            // Update row classes
            opts.isDataChange = true;
            this._render_status(opts);
            // Let user modify the result
            if (this.statusNodeType) {
                this._callEvent("renderStatusNode", {
                    isNew: isNew,
                    nodeElem: nodeElem,
                    isColspan: isColspan,
                });
            }
            else if (this.parent) {
                // Skip root node
                const renderInfo = this._getRenderInfo();
                this._callEvent("render", {
                    isNew: isNew,
                    nodeElem: nodeElem,
                    isColspan: isColspan,
                    allColInfosById: renderInfo.allColInfosById,
                    renderColInfosById: renderInfo.renderColInfosById,
                });
            }
        }
        /**
         * Update row classes to reflect active, focuses, etc.
         * @see {@link WunderbaumNode._render}
         */
        _render_status(opts) {
            // this.log("_render_status", opts);
            const tree = this.tree;
            const iconMap = tree.iconMap;
            const treeOptions = tree.options;
            const typeInfo = this.type ? tree.types[this.type] : null;
            const rowDiv = this._rowElem;
            // Row markup already exists
            const nodeElem = rowDiv.querySelector("span.wb-node");
            const expanderSpan = nodeElem.querySelector("i.wb-expander");
            const checkboxSpan = nodeElem.querySelector("i.wb-checkbox");
            const rowClasses = ["wb-row"];
            this.expanded ? rowClasses.push("wb-expanded") : 0;
            this.lazy ? rowClasses.push("wb-lazy") : 0;
            this.selected ? rowClasses.push("wb-selected") : 0;
            this._partsel ? rowClasses.push("wb-partsel") : 0;
            this === tree.activeNode ? rowClasses.push("wb-active") : 0;
            this === tree.focusNode ? rowClasses.push("wb-focus") : 0;
            this._errorInfo ? rowClasses.push("wb-error") : 0;
            this._isLoading ? rowClasses.push("wb-loading") : 0;
            this.isColspan() ? rowClasses.push("wb-colspan") : 0;
            this.statusNodeType
                ? rowClasses.push("wb-status-" + this.statusNodeType)
                : 0;
            this.match ? rowClasses.push("wb-match") : 0;
            this.subMatchCount ? rowClasses.push("wb-submatch") : 0;
            treeOptions.skeleton ? rowClasses.push("wb-skeleton") : 0;
            // Replace previous classes:
            rowDiv.className = rowClasses.join(" ");
            // Add classes from `node.classes`
            this.classes ? rowDiv.classList.add(...this.classes) : 0;
            // Add classes from `tree.types[node.type]`
            if (typeInfo && typeInfo.classes) {
                rowDiv.classList.add(...typeInfo.classes);
            }
            if (expanderSpan) {
                let image = null;
                if (this._isLoading) {
                    image = iconMap.loading;
                }
                else if (this.isExpandable(false)) {
                    if (this.expanded) {
                        image = iconMap.expanderExpanded;
                    }
                    else {
                        image = iconMap.expanderCollapsed;
                    }
                }
                else if (this.lazy && this.children == null) {
                    image = iconMap.expanderLazy;
                }
                if (image == null) {
                    expanderSpan.classList.add("wb-indent");
                }
                else if (TEST_IMG.test(image)) {
                    expanderSpan.style.backgroundImage = `url('${image}')`;
                }
                else {
                    expanderSpan.className = "wb-expander " + image;
                }
            }
            if (checkboxSpan) {
                let cbclass = "wb-checkbox ";
                if (this.isRadio()) {
                    cbclass += "wb-radio ";
                    if (this.selected) {
                        cbclass += iconMap.radioChecked;
                        // } else if (this._partsel) {
                        //   cbclass += iconMap.radioUnknown;
                    }
                    else {
                        cbclass += iconMap.radioUnchecked;
                    }
                }
                else {
                    if (this.selected) {
                        cbclass += iconMap.checkChecked;
                    }
                    else if (this._partsel) {
                        cbclass += iconMap.checkUnknown;
                    }
                    else {
                        cbclass += iconMap.checkUnchecked;
                    }
                }
                checkboxSpan.className = cbclass;
            }
            // Fix active cell in cell-nav mode
            if (!opts.isNew) {
                let i = 0;
                for (const colSpan of rowDiv.children) {
                    colSpan.classList.toggle("wb-active", i++ === tree.activeColIdx);
                    colSpan.classList.remove("wb-error", "wb-invalid");
                }
                // Update icon (if not opts.isNew, which would rebuild markup anyway)
                const iconSpan = nodeElem.querySelector("i.wb-icon");
                if (iconSpan) {
                    this._createIcon(tree.iconMap, nodeElem, iconSpan, !expanderSpan);
                }
            }
            // Adjust column width
            if (opts.resizeCols !== false && !this.isColspan()) {
                const colElems = rowDiv.querySelectorAll("span.wb-col");
                let idx = 0;
                let ofs = 0;
                for (const colDef of this.tree.columns) {
                    const colElem = colElems[idx];
                    colElem.style.left = `${ofs}px`;
                    colElem.style.width = `${colDef._widthPx}px`;
                    idx++;
                    ofs += colDef._widthPx;
                }
            }
        }
        /*
         * Create or update node's markup.
         *
         * `options.change` defaults to ChangeType.data, which updates the title,
         * icon, and status. It also triggers the `render` event, that lets the user
         * create or update the content of embeded cell elements.
         *
         * If only the status or other class-only modifications have changed,
         * `options.change` should be set to ChangeType.status instead for best
         * efficiency.
         *
         * Calling `update()` is almost always a better alternative.
         * @see {@link WunderbaumNode.update}
         */
        _render(options) {
            // this.log("render", options);
            const opts = Object.assign({ change: ChangeType.data }, options);
            if (!this._rowElem) {
                opts.change = ChangeType.row;
            }
            switch (opts.change) {
                case "status":
                    this._render_status(opts);
                    break;
                case "data":
                    this._render_data(opts);
                    break;
                case "row":
                    // _rowElem is not yet created (asserted in _render_markup)
                    this._render_markup(opts);
                    break;
                default:
                    error(`Invalid change type '${opts.change}'.`);
            }
        }
        /**
         * Remove all children, collapse, and set the lazy-flag, so that the lazyLoad
         * event is triggered on next expand.
         */
        resetLazy() {
            this.removeChildren();
            this.expanded = false;
            this.lazy = true;
            this.children = null;
            this.tree.update(ChangeType.structure);
        }
        /** Convert node (or whole branch) into a plain object.
         *
         * The result is compatible with node.addChildren().
         *
         * @param include child nodes
         * @param callback(dict, node) is called for every node, in order to allow
         *     modifications.
         *     Return `false` to ignore this node or `"skip"` to include this node
         *     without its children.
         * @see {@link Wunderbaum.toDictArray}.
         */
        toDict(recursive = false, callback) {
            const dict = {};
            NODE_DICT_PROPS.forEach((propName) => {
                const val = this[propName];
                if (val instanceof Set) {
                    // Convert Set to string (or skip if set is empty)
                    val.size
                        ? (dict[propName] = Array.prototype.join.call(val.keys(), " "))
                        : 0;
                }
                else if (val || val === false || val === 0) {
                    dict[propName] = val;
                }
            });
            if (!isEmptyObject(this.data)) {
                dict.data = extend({}, this.data);
                if (isEmptyObject(dict.data)) {
                    delete dict.data;
                }
            }
            if (callback) {
                const res = callback(dict, this);
                if (res === false) {
                    // Note: a return value of `false` is only used internally
                    return false; // Don't include this node nor its children
                }
                if (res === "skip") {
                    recursive = false; // Include this node, but not the children
                }
            }
            if (recursive) {
                if (isArray(this.children)) {
                    dict.children = [];
                    for (let i = 0, l = this.children.length; i < l; i++) {
                        const node = this.children[i];
                        if (!node.isStatusNode()) {
                            // Note: a return value of `false` is only used internally
                            const res = node.toDict(true, callback);
                            if (res !== false) {
                                dict.children.push(res);
                            }
                        }
                    }
                }
            }
            return dict;
        }
        /** Return an option value that has a default, but may be overridden by a
         * callback or a node instance attribute.
         *
         * Evaluation sequence:
         *
         * - If `tree.options.<name>` is a callback that returns something, use that.
         * - Else if `node.<name>` is defined, use that.
         * - Else if `tree.types[<node.type>]` is a value, use that.
         * - Else if `tree.options.<name>` is a value, use that.
         * - Else use `defaultValue`.
         *
         * @param name name of the option property (on node and tree)
         * @param defaultValue return this if nothing else matched
         * {@link Wunderbaum.getOption|Wunderbaum.getOption()}
         */
        getOption(name, defaultValue) {
            const tree = this.tree;
            let opts = tree.options;
            // Lookup `name` in options dict
            if (name.indexOf(".") >= 0) {
                [opts, name] = name.split(".");
            }
            const value = opts[name]; // ?? defaultValue;
            // A callback resolver always takes precedence
            if (typeof value === "function") {
                const res = value.call(tree, {
                    type: "resolve",
                    tree: tree,
                    node: this,
                    // typeInfo: this.type ? tree.types[this.type] : {},
                });
                if (res !== undefined) {
                    return res;
                }
            }
            // If this node has an explicit local setting, use it:
            if (this[name] !== undefined) {
                return this[name];
            }
            // Use value from type definition if defined
            const typeInfo = this.type ? tree.types[this.type] : undefined;
            const res = typeInfo ? typeInfo[name] : undefined;
            if (res !== undefined) {
                return res;
            }
            // Use value from value options dict, fallback do default
            return value !== null && value !== void 0 ? value : defaultValue;
        }
        /** Make sure that this node is visible in the viewport.
         * @see {@link Wunderbaum.scrollTo|Wunderbaum.scrollTo()}
         */
        async scrollIntoView(options) {
            const opts = Object.assign({ node: this }, options);
            return this.tree.scrollTo(opts);
        }
        /**
         * Activate this node, deactivate previous, send events, activate column and
         * scroll into viewport.
         */
        async setActive(flag = true, options) {
            const tree = this.tree;
            const prev = tree.getActiveNode();
            const retrigger = options === null || options === void 0 ? void 0 : options.retrigger; // Default: false
            const focusTree = options === null || options === void 0 ? void 0 : options.focusTree; // Default: false
            // const focusNode = options?.focusNode !== false; // Default: true
            const noEvents = options === null || options === void 0 ? void 0 : options.noEvents; // Default: false
            const orgEvent = options === null || options === void 0 ? void 0 : options.event; // Default: null
            const colIdx = options === null || options === void 0 ? void 0 : options.colIdx; // Default: null
            const edit = options === null || options === void 0 ? void 0 : options.edit; // Default: false
            assert(!colIdx || tree.isCellNav(), "colIdx requires cellNav");
            assert(!edit || colIdx != null, "edit requires colIdx");
            if (!noEvents) {
                if (flag) {
                    if (prev !== this || retrigger) {
                        if ((prev === null || prev === void 0 ? void 0 : prev._callEvent("deactivate", {
                            nextNode: this,
                            event: orgEvent,
                        })) === false ||
                            this._callEvent("beforeActivate", {
                                prevNode: prev,
                                event: orgEvent,
                            }) === false) {
                            return;
                        }
                        tree._setActiveNode(null);
                        prev === null || prev === void 0 ? void 0 : prev.update(ChangeType.status);
                    }
                }
                else if (prev === this || retrigger) {
                    this._callEvent("deactivate", { nextNode: null, event: orgEvent });
                }
            }
            if (prev !== this) {
                if (flag) {
                    tree._setActiveNode(this);
                }
                prev === null || prev === void 0 ? void 0 : prev.update(ChangeType.status);
                this.update(ChangeType.status);
            }
            return this.makeVisible().then(() => {
                if (flag) {
                    if (focusTree || edit) {
                        tree.setFocus();
                        tree._setFocusNode(this);
                        tree.focusNode.setFocus();
                    }
                    // if (focusNode || edit) {
                    //   tree.focusNode = this;
                    //   tree.focusNode.setFocus();
                    // }
                    if (colIdx != null && tree.isCellNav()) {
                        tree.setColumn(colIdx, { edit: edit });
                    }
                    if (!noEvents) {
                        this._callEvent("activate", { prevNode: prev, event: orgEvent });
                    }
                }
            });
        }
        /**
         * Expand or collapse this node.
         */
        async setExpanded(flag = true, options) {
            const { force, scrollIntoView, immediate } = options !== null && options !== void 0 ? options : {};
            const sendEvents = !(options === null || options === void 0 ? void 0 : options.noEvents); // Default: send events
            if (!flag &&
                this.isExpanded() &&
                this.getLevel() <= this.tree.getOption("minExpandLevel") &&
                !force) {
                this.logDebug("Ignored collapse request below minExpandLevel.");
                return;
            }
            if (!flag === !this.expanded) {
                return; // Nothing to do
            }
            if (sendEvents &&
                this._callEvent("beforeExpand", { flag: flag }) === false) {
                return;
            }
            // this.log("setExpanded()");
            if (flag && this.getOption("autoCollapse")) {
                this.collapseSiblings(options);
            }
            if (flag && this.lazy && this.children == null) {
                await this.loadLazy();
            }
            this.expanded = flag;
            const updateOpts = { immediate: immediate };
            // const updateOpts = { immediate: !!util.getOption(options, "immediate") };
            this.tree.update(ChangeType.structure, updateOpts);
            if (flag && scrollIntoView) {
                const lastChild = this.getLastChild();
                if (lastChild) {
                    this.tree.updatePendingModifications();
                    lastChild.scrollIntoView({ topNode: this });
                }
            }
            if (sendEvents) {
                this._callEvent("expand", { flag: flag });
            }
        }
        /**
         * Set keyboard focus here.
         * @see {@link setActive}
         */
        setFocus(flag = true) {
            assert(!!flag, "Blur is not yet implemented");
            const prev = this.tree.focusNode;
            this.tree._setFocusNode(this);
            prev === null || prev === void 0 ? void 0 : prev.update();
            this.update();
        }
        /** Set a new icon path or class. */
        setIcon(icon) {
            this.icon = icon;
            this.update();
        }
        /** Change node's {@link key} and/or {@link refKey}.  */
        setKey(key, refKey) {
            throw new Error("Not yet implemented");
        }
        /**
         * Trigger a repaint, typically after a status or data change.
         *
         * `change` defaults to 'data', which handles modifcations of title, icon,
         * and column content. It can be reduced to 'ChangeType.status' if only
         * active/focus/selected state has changed.
         *
         * This method will eventually call  {@link WunderbaumNode._render()} with
         * default options, but may be more consistent with the tree's
         * {@link Wunderbaum.update()} API.
         */
        update(change = ChangeType.data) {
            assert(change === ChangeType.status || change === ChangeType.data, `Invalid change type ${change}`);
            this.tree.update(change, this);
        }
        /**
         * Return an array of selected nodes.
         * @param stopOnParents only return the topmost selected node (useful with selectMode 'hier')
         */
        getSelectedNodes(stopOnParents = false) {
            const nodeList = [];
            this.visit((node) => {
                if (node.selected) {
                    nodeList.push(node);
                    if (stopOnParents === true) {
                        return "skip"; // stop processing this branch
                    }
                }
            });
            return nodeList;
        }
        /** Toggle the check/uncheck state. */
        toggleSelected(options) {
            let flag = this.isSelected();
            if (flag === undefined && !this.isRadio()) {
                flag = this._anySelectable();
            }
            else {
                flag = !flag;
            }
            return this.setSelected(flag, options);
        }
        /** Return true if at least on selectable descendant end-node is unselected. @internal */
        _anySelectable() {
            let found = false;
            this.visit((node) => {
                if (node.selected === false &&
                    !node.unselectable &&
                    !node.hasChildren() &&
                    !node.parent.radiogroup) {
                    found = true;
                    return false; // Stop iteration
                }
            });
            return found;
        }
        /* Apply selection state to a single node. */
        _changeSelectStatusProps(state) {
            let changed = false;
            switch (state) {
                case false:
                    changed = this.selected || this._partsel;
                    this.selected = false;
                    this._partsel = false;
                    break;
                case true:
                    changed = !this.selected || !this._partsel;
                    this.selected = true;
                    this._partsel = true;
                    break;
                case undefined:
                    changed = this.selected || !this._partsel;
                    this.selected = false;
                    this._partsel = true;
                    break;
                default:
                    error(`Invalid state: ${state}`);
            }
            if (changed) {
                this.update();
            }
            return changed;
        }
        /**
         * Fix selection status, after this node was (de)selected in `selectMode: 'hier'`.
         * This includes (de)selecting all descendants.
         */
        fixSelection3AfterClick(opts) {
            const force = !!(opts === null || opts === void 0 ? void 0 : opts.force);
            const flag = this.isSelected();
            this.visit((node) => {
                if (node.radiogroup) {
                    return "skip"; // Don't (de)select this branch
                }
                if (force || !node.getOption("unselectable")) {
                    node._changeSelectStatusProps(flag);
                }
            });
            this.fixSelection3FromEndNodes();
        }
        /**
         * Fix selection status for multi-hier mode.
         * Only end-nodes are considered to update the descendants branch and parents.
         * Should be called after this node has loaded new children or after
         * children have been modified using the API.
         */
        fixSelection3FromEndNodes(opts) {
            const force = !!(opts === null || opts === void 0 ? void 0 : opts.force);
            assert(this.tree.options.selectMode === "hier", "expected selectMode 'hier'");
            // Visit all end nodes and adjust their parent's `selected` and `_partsel`
            // attributes. Return selection state true, false, or undefined.
            const _walk = (node) => {
                let state;
                const children = node.children;
                if (children && children.length) {
                    // check all children recursively
                    let allSelected = true;
                    let someSelected = false;
                    for (let i = 0, l = children.length; i < l; i++) {
                        const child = children[i];
                        // the selection state of a node is not relevant; we need the end-nodes
                        const s = _walk(child);
                        if (s !== false) {
                            someSelected = true;
                        }
                        if (s !== true) {
                            allSelected = false;
                        }
                    }
                    state = allSelected ? true : someSelected ? undefined : false;
                }
                else {
                    // This is an end-node: simply report the status
                    state = !!node.selected;
                }
                // #939: Keep a `_partsel` flag that was explicitly set on a lazy node
                if (node._partsel &&
                    !node.selected &&
                    node.lazy &&
                    node.children == null) {
                    state = undefined;
                }
                if (force || !node.getOption("unselectable")) {
                    node._changeSelectStatusProps(state);
                }
                return state;
            };
            _walk(this);
            // Update parent's state
            this.visitParents((node) => {
                let state;
                const children = node.children;
                let allSelected = true;
                let someSelected = false;
                for (let i = 0, l = children.length; i < l; i++) {
                    const child = children[i];
                    state = !!child.selected;
                    // When fixing the parents, we trust the sibling status (i.e. we don't recurse)
                    if (state || child._partsel) {
                        someSelected = true;
                    }
                    if (!state) {
                        allSelected = false;
                    }
                }
                state = allSelected ? true : someSelected ? undefined : false;
                node._changeSelectStatusProps(state);
            });
        }
        /** Modify the check/uncheck state. */
        setSelected(flag = true, options) {
            const tree = this.tree;
            const sendEvents = !(options === null || options === void 0 ? void 0 : options.noEvents); // Default: send events
            const prev = this.isSelected();
            const isRadio = this.parent && this.parent.radiogroup;
            const selectMode = tree.options.selectMode;
            const canSelect = (options === null || options === void 0 ? void 0 : options.force) || !this.getOption("unselectable");
            flag = !!flag;
            // this.logDebug(`setSelected(${flag})`, this);
            if (!canSelect) {
                return prev;
            }
            if ((options === null || options === void 0 ? void 0 : options.propagateDown) && selectMode === "multi") {
                tree.runWithDeferredUpdate(() => {
                    this.visit((node) => {
                        node.setSelected(flag);
                    });
                });
                return prev;
            }
            if (flag === prev ||
                (sendEvents && this._callEvent("beforeSelect", { flag: flag }) === false)) {
                return prev;
            }
            tree.runWithDeferredUpdate(() => {
                if (isRadio) {
                    // Radiobutton Group
                    if (!flag && !(options === null || options === void 0 ? void 0 : options.force)) {
                        return prev; // don't uncheck radio buttons
                    }
                    for (const sibling of this.parent.children) {
                        sibling.selected = sibling === this;
                    }
                }
                else {
                    this.selected = flag;
                    if (selectMode === "hier") {
                        this.fixSelection3AfterClick();
                    }
                    else if (selectMode === "single") {
                        tree.visit((n) => {
                            n.selected = false;
                        });
                    }
                }
            });
            if (sendEvents) {
                this._callEvent("select", { flag: flag });
            }
            return prev;
        }
        /** Display node status (ok, loading, error, noData) using styles and a dummy child node. */
        setStatus(status, options) {
            const tree = this.tree;
            const message = options === null || options === void 0 ? void 0 : options.message;
            const details = options === null || options === void 0 ? void 0 : options.details;
            let statusNode = null;
            const _clearStatusNode = () => {
                // Remove dedicated dummy node, if any
                const children = this.children;
                if (children && children.length && children[0].isStatusNode()) {
                    children[0].remove();
                }
            };
            const _setStatusNode = (data) => {
                // Create/modify the dedicated dummy node for 'loading...' or
                // 'error!' status. (only called for direct child of the invisible
                // system root)
                const children = this.children;
                const firstChild = children ? children[0] : null;
                assert(data.statusNodeType, "Not a status node");
                assert(!firstChild || !firstChild.isStatusNode(), "Child must not be a status node");
                statusNode = this.addNode(data, "prependChild");
                statusNode.match = true;
                tree.update(ChangeType.structure);
                return statusNode;
            };
            _clearStatusNode();
            switch (status) {
                case "ok":
                    this._isLoading = false;
                    this._errorInfo = null;
                    break;
                case "loading":
                    this._isLoading = true;
                    this._errorInfo = null;
                    if (this.parent) {
                        this.update(ChangeType.status);
                    }
                    else {
                        // If this is the invisible root, add a visible top-level node
                        _setStatusNode({
                            statusNodeType: status,
                            title: tree.options.strings.loading +
                                (message ? " (" + message + ")" : ""),
                            checkbox: false,
                            colspan: true,
                            tooltip: details,
                        });
                    }
                    // this.update();
                    break;
                case "error":
                    _setStatusNode({
                        statusNodeType: status,
                        title: tree.options.strings.loadError +
                            (message ? " (" + message + ")" : ""),
                        checkbox: false,
                        colspan: true,
                        // classes: "wb-center",
                        tooltip: details,
                    });
                    this._isLoading = false;
                    this._errorInfo = { message: message, details: details };
                    break;
                case "noData":
                    _setStatusNode({
                        statusNodeType: status,
                        title: message || tree.options.strings.noData,
                        checkbox: false,
                        colspan: true,
                        tooltip: details,
                    });
                    this._isLoading = false;
                    this._errorInfo = null;
                    break;
                default:
                    error("invalid node status " + status);
            }
            tree.update(ChangeType.structure);
            return statusNode;
        }
        /** Rename this node. */
        setTitle(title) {
            this.title = title;
            this.update();
            // this.triggerModify("rename"); // TODO
        }
        _sortChildren(cmp, deep) {
            const cl = this.children;
            if (!cl) {
                return;
            }
            cl.sort(cmp);
            if (deep) {
                for (let i = 0, l = cl.length; i < l; i++) {
                    if (cl[i].children) {
                        cl[i]._sortChildren(cmp, deep);
                    }
                }
            }
        }
        /**
         * Sort child list by title or custom criteria.
         * @param {function} cmp custom compare function(a, b) that returns -1, 0, or 1
         *    (defaults to sorting by title).
         * @param {boolean} deep pass true to sort all descendant nodes recursively
         */
        sortChildren(cmp = nodeTitleSorter, deep = false) {
            this._sortChildren(cmp || nodeTitleSorter, deep);
            this.tree.update(ChangeType.structure);
            // this.triggerModify("sort"); // TODO
        }
        /**
         * Trigger `modifyChild` event on a parent to signal that a child was modified.
         * @param {string} operation Type of change: 'add', 'remove', 'rename', 'move', 'data', ...
         */
        triggerModifyChild(operation, child, extra) {
            this.logDebug(`modifyChild(${operation})`, extra, child);
            if (!this.tree.options.modifyChild) {
                return;
            }
            if (child && child.parent !== this) {
                error("child " + child + " is not a child of " + this);
            }
            this._callEvent("modifyChild", extend({ operation: operation, child: child }, extra));
        }
        /**
         * Trigger `modifyChild` event on node.parent(!).
         * @param {string} operation Type of change: 'add', 'remove', 'rename', 'move', 'data', ...
         * @param {object} [extra]
         */
        triggerModify(operation, extra) {
            // if (!this.parent) {
            //   return;
            // }
            this.parent.triggerModifyChild(operation, this, extra);
        }
        /**
         * Call `callback(node)` for all descendant nodes in hierarchical order (depth-first, pre-order).
         *
         * Stop iteration, if fn() returns false. Skip current branch, if fn()
         * returns "skip".<br>
         * Return false if iteration was stopped.
         *
         * @param {function} callback the callback function.
         *     Return false to stop iteration, return "skip" to skip this node and
         *     its children only.
         * @see {@link IterableIterator<WunderbaumNode>}, {@link Wunderbaum.visit}.
         */
        visit(callback, includeSelf = false) {
            let res = true;
            const children = this.children;
            if (includeSelf === true) {
                res = callback(this);
                if (res === false || res === "skip") {
                    return res;
                }
            }
            if (children) {
                for (let i = 0, l = children.length; i < l; i++) {
                    res = children[i].visit(callback, true);
                    if (res === false) {
                        break;
                    }
                }
            }
            return res;
        }
        /** Call fn(node) for all parent nodes, bottom-up, including invisible system root.<br>
         * Stop iteration, if callback() returns false.<br>
         * Return false if iteration was stopped.
         *
         * @param callback the callback function. Return false to stop iteration
         */
        visitParents(callback, includeSelf = false) {
            if (includeSelf && callback(this) === false) {
                return false;
            }
            let p = this.parent;
            while (p) {
                if (callback(p) === false) {
                    return false;
                }
                p = p.parent;
            }
            return true;
        }
        /**
         * Call fn(node) for all sibling nodes.<br>
         * Stop iteration, if fn() returns false.<br>
         * Return false if iteration was stopped.
         *
         * @param {function} fn the callback function.
         *     Return false to stop iteration.
         */
        visitSiblings(callback, includeSelf = false) {
            const ac = this.parent.children;
            for (let i = 0, l = ac.length; i < l; i++) {
                const n = ac[i];
                if (includeSelf || n !== this) {
                    if (callback(n) === false) {
                        return false;
                    }
                }
            }
            return true;
        }
        /**
         * [ext-filter] Return true if this node is matched by current filter (or no filter is active).
         */
        isMatched() {
            return !(this.tree.filterMode && !this.match);
        }
    }
    WunderbaumNode.sequence = 0;

    /*!
     * Wunderbaum - ext-edit
     * Copyright (c) 2021-2023, Martin Wendt. Released under the MIT license.
     * v0.8.2, Sat, 17 Feb 2024 07:32:06 GMT (https://github.com/mar10/wunderbaum)
     */
    // const START_MARKER = "\uFFF7";
    class EditExtension extends WunderbaumExtension {
        constructor(tree) {
            super(tree, "edit", {
                debounce: 100,
                minlength: 1,
                maxlength: null,
                trigger: [],
                trim: true,
                select: true,
                slowClickDelay: 1000,
                validity: true,
                // --- Events ---
                // (note: there is also the `tree.change` event.)
                beforeEdit: null,
                edit: null,
                apply: null,
            });
            this.curEditNode = null;
            this.relatedNode = null;
            this.debouncedOnChange = debounce(this._onChange.bind(this), this.getPluginOption("debounce"));
        }
        /*
         * Call an event handler, while marking the current node cell 'busy'.
         * Deal with returned promises and ValidationError.
         * Convert a ValidationError into a input.setCustomValidity() call and vice versa.
         */
        async _applyChange(eventName, node, colElem, inputElem, extra) {
            node.log(`_applyChange(${eventName})`, extra);
            colElem.classList.add("wb-busy");
            colElem.classList.remove("wb-error", "wb-invalid");
            inputElem.setCustomValidity("");
            // Call event handler either ('change' or 'edit.appy'), which may return a
            // promise or a scalar value or throw a ValidationError.
            return new Promise((resolve, reject) => {
                const res = node._callEvent(eventName, extra);
                // normalize to promise, even if a scalar value was returned and await it
                Promise.resolve(res)
                    .then((res) => {
                    resolve(res);
                })
                    .catch((err) => {
                    reject(err);
                });
            })
                .then((res) => {
                if (!inputElem.checkValidity()) {
                    // Native validation failed or handler called 'inputElem.setCustomValidity()'
                    node.logWarn("inputElem.checkValidity() failed: throwing....");
                    throw new ValidationError(inputElem.validationMessage);
                }
                return res;
            })
                .catch((err) => {
                if (err instanceof ValidationError) {
                    node.logWarn("catched ", err);
                    colElem.classList.add("wb-invalid");
                    if (inputElem.setCustomValidity && !inputElem.validationMessage) {
                        inputElem.setCustomValidity(err.message);
                    }
                    if (inputElem.validationMessage) {
                        inputElem.reportValidity();
                    }
                    // throw err;
                }
                else {
                    node.logError(`Error in ${eventName} event handler (throw e.util.ValidationError instead if this was intended)`, err);
                    colElem.classList.add("wb-error");
                    throw err;
                }
            })
                .finally(() => {
                colElem.classList.remove("wb-busy");
            });
        }
        /*
         * Called for when a control that is embedded in a cell fires a `change` event.
         */
        _onChange(e) {
            const info = Wunderbaum.getEventInfo(e);
            const node = info.node;
            const colElem = info.colElem;
            if (!node || info.colIdx === 0) {
                this.tree.log("Ignored change event for removed element or node title");
                return;
            }
            // See also WbChangeEventType
            this._applyChange("change", node, colElem, e.target, {
                info: info,
                event: e,
                inputElem: e.target,
                inputValue: Wunderbaum.util.getValueFromElem(e.target),
                inputValid: e.target.checkValidity(),
            });
        }
        init() {
            super.init();
            onEvent(this.tree.element, "change", //"change input",
            ".contenteditable,input,textarea,select",
            // #61: we must not debounce the `change`, event.target may be reset to null
            // when the debounced handler is called.
            // (e) => {
            //   this.debouncedOnChange(e);
            // }
            (e) => this._onChange(e));
        }
        /* Called by ext_keynav to pre-process input. */
        _preprocessKeyEvent(data) {
            const event = data.event;
            const eventName = eventToString(event);
            const tree = this.tree;
            const trigger = this.getPluginOption("trigger");
            // const inputElem =
            //   event.target && event.target.closest("input,[contenteditable]");
            // tree.logDebug(`_preprocessKeyEvent: ${eventName}, editing:${this.isEditingTitle()}`);
            // --- Title editing: apply/discard ---
            // if (inputElem) {
            if (this.isEditingTitle()) {
                switch (eventName) {
                    case "Enter":
                        this._stopEditTitle(true, { event: event });
                        return false;
                    case "Escape":
                        this._stopEditTitle(false, { event: event });
                        return false;
                }
                // If the event target is an input element or `contenteditable="true"`,
                // we ignore it as navigation command
                return false;
            }
            // --- Trigger title editing
            if (tree.isRowNav() || tree.activeColIdx === 0) {
                switch (eventName) {
                    case "Enter":
                        if (trigger.indexOf("macEnter") >= 0 && isMac) {
                            this.startEditTitle();
                            return false;
                        }
                        break;
                    case "F2":
                        if (trigger.indexOf("F2") >= 0) {
                            this.startEditTitle();
                            return false;
                        }
                        break;
                }
                return true;
            }
            return true;
        }
        /** Return true if a title is currently being edited. */
        isEditingTitle(node) {
            return node ? this.curEditNode === node : !!this.curEditNode;
        }
        /** Start renaming, i.e. replace the title with an embedded `<input>`. */
        startEditTitle(node) {
            node = node !== null && node !== void 0 ? node : this.tree.getActiveNode();
            const validity = this.getPluginOption("validity");
            const select = this.getPluginOption("select");
            if (!node) {
                return;
            }
            this.tree.logDebug(`startEditTitle(node=${node})`);
            let inputHtml = node._callEvent("edit.beforeEdit");
            if (inputHtml === false) {
                node.logDebug("beforeEdit canceled operation.");
                return;
            }
            // `beforeEdit(e)` may return an input HTML string. Otherwise use a default
            // (we also treat a `true` return value as 'use default'):
            if (inputHtml === true || !inputHtml) {
                const title = escapeHtml(node.title);
                let opt = this.getPluginOption("maxlength");
                const maxlength = opt ? ` maxlength="${opt}"` : "";
                opt = this.getPluginOption("minlength");
                const minlength = opt ? ` minlength="${opt}"` : "";
                const required = opt > 0 ? " required" : "";
                inputHtml =
                    `<input type=text class="wb-input-edit" tabindex=-1 value="${title}" ` +
                        `autocorrect="off"${required}${minlength}${maxlength} >`;
            }
            const titleSpan = node
                .getColElem(0)
                .querySelector(".wb-title");
            titleSpan.innerHTML = inputHtml;
            const inputElem = titleSpan.firstElementChild;
            if (validity) {
                // Permanently apply input validations (CSS and tooltip)
                inputElem.addEventListener("keydown", (e) => {
                    inputElem.setCustomValidity("");
                    if (!inputElem.reportValidity()) {
                        node.logWarn(`Invalid input: '${inputElem.value}'`);
                    }
                });
            }
            inputElem.focus();
            if (select) {
                inputElem.select();
            }
            this.curEditNode = node;
            node._callEvent("edit.edit", {
                inputElem: inputElem,
            });
        }
        /**
         *
         * @param apply
         * @returns
         */
        stopEditTitle(apply) {
            return this._stopEditTitle(apply, {});
        }
        /*
         *
         * @param apply
         * @param opts.canKeepOpen
         */
        _stopEditTitle(apply, options) {
            options !== null && options !== void 0 ? options : (options = {});
            const focusElem = document.activeElement;
            let newValue = focusElem ? getValueFromElem(focusElem) : null;
            const node = this.curEditNode;
            const forceClose = !!options.forceClose;
            const validity = this.getPluginOption("validity");
            if (newValue && this.getPluginOption("trim")) {
                newValue = newValue.trim();
            }
            if (!node) {
                this.tree.logDebug("stopEditTitle: not in edit mode.");
                return;
            }
            node.logDebug(`stopEditTitle(${apply})`, options, focusElem, newValue);
            if (apply && newValue !== null && newValue !== node.title) {
                const errMsg = focusElem.validationMessage;
                if (errMsg) {
                    // input element's native validation failed
                    throw new Error(`Input validation failed for "${newValue}": ${errMsg}.`);
                }
                const colElem = node.getColElem(0);
                this._applyChange("edit.apply", node, colElem, focusElem, {
                    oldValue: node.title,
                    newValue: newValue,
                    inputElem: focusElem,
                    inputValid: focusElem.checkValidity(),
                }).then((value) => {
                    const errMsg = focusElem.validationMessage;
                    if (validity && errMsg && value !== false) {
                        // Handler called 'inputElem.setCustomValidity()' to signal error
                        throw new Error(`Edit apply validation failed for "${newValue}": ${errMsg}.`);
                    }
                    // Discard the embedded `<input>`
                    // node.logDebug("applyChange:", value, forceClose)
                    if (!forceClose && value === false) {
                        // Keep open
                        return;
                    }
                    node === null || node === void 0 ? void 0 : node.setTitle(newValue);
                    // NOTE: At least on Safari, this render call triggers a scroll event
                    // probably because the focused input is replaced.
                    this.curEditNode._render({ preventScroll: true });
                    this.curEditNode = null;
                    this.relatedNode = null;
                    this.tree.setFocus(); // restore focus that was in the input element
                });
                // .catch((err) => {
                //   node.logError(err);
                // });
                // Trigger 'change' event for embedded `<input>`
                // focusElem.blur();
            }
            else {
                // Discard the embedded `<input>`
                // NOTE: At least on Safari, this render call triggers a scroll event
                // probably because the focused input is replaced.
                this.curEditNode._render({ preventScroll: true });
                this.curEditNode = null;
                this.relatedNode = null;
                // We discarded the <input>, so we have to acquire keyboard focus again
                this.tree.setFocus();
            }
        }
        /**
         * Create a new child or sibling node and start edit mode.
         */
        createNode(mode = "after", node, init) {
            const tree = this.tree;
            node = node !== null && node !== void 0 ? node : tree.getActiveNode();
            assert(node, "No node was passed, or no node is currently active.");
            // const validity = this.getPluginOption("validity");
            mode = mode || "prependChild";
            if (init == null) {
                init = { title: "" };
            }
            else if (typeof init === "string") {
                init = { title: init };
            }
            else {
                assert(isPlainObject(init), `Expected a plain object: ${init}`);
            }
            // Make sure node is expanded (and loaded) in 'child' mode
            if ((mode === "prependChild" || mode === "appendChild") &&
                (node === null || node === void 0 ? void 0 : node.isExpandable(true))) {
                node.setExpanded().then(() => {
                    this.createNode(mode, node, init);
                });
                return;
            }
            const newNode = node.addNode(init, mode);
            newNode.setClass("wb-edit-new");
            this.relatedNode = node;
            // Don't filter new nodes:
            newNode.match = true;
            newNode.makeVisible({ noAnimation: true }).then(() => {
                this.startEditTitle(newNode);
            });
        }
    }

    /*!
     * wunderbaum.ts
     *
     * A treegrid control.
     *
     * Copyright (c) 2021-2023, Martin Wendt (https://wwWendt.de).
     * https://github.com/mar10/wunderbaum
     *
     * Released under the MIT license.
     * @version v0.8.2
     * @date Sat, 17 Feb 2024 07:32:06 GMT
     */
    // import "./wunderbaum.scss";
    class WbSystemRoot extends WunderbaumNode {
        constructor(tree) {
            super(tree, null, {
                key: "__root__",
                title: tree.id,
            });
        }
        toString() {
            return `WbSystemRoot@${this.key}<'${this.tree.id}'>`;
        }
    }
    /**
     * A persistent plain object or array.
     *
     * See also {@link WunderbaumOptions}.
     */
    class Wunderbaum {
        /** Currently active node if any.
         * Use @link {WunderbaumNode.setActive|setActive} to modify.
         */
        get activeNode() {
            var _a;
            // Check for deleted node, i.e. node.tree === null
            return ((_a = this._activeNode) === null || _a === void 0 ? void 0 : _a.tree) ? this._activeNode : null;
        }
        /** Current node hat has keyboard focus if any.
         * Use @link {WunderbaumNode.setFocus|setFocus()} to modify.
         */
        get focusNode() {
            var _a;
            // Check for deleted node, i.e. node.tree === null
            return ((_a = this._focusNode) === null || _a === void 0 ? void 0 : _a.tree) ? this._focusNode : null;
        }
        constructor(options) {
            this.enabled = true;
            /** Contains additional data that was sent as response to an Ajax source load request. */
            this.data = {};
            this.extensionList = [];
            this.extensions = {};
            this.keyMap = new Map();
            this.refKeyMap = new Map();
            this.treeRowCount = 0;
            this._disableUpdateCount = 0;
            this._disableUpdateIgnoreCount = 0;
            this._activeNode = null;
            this._focusNode = null;
            /** Shared properties, referenced by `node.type`. */
            this.types = {};
            /** List of column definitions. */
            this.columns = []; // any[] = [];
            this._columnsById = {};
            // Modification Status
            this.pendingChangeTypes = new Set();
            /** Expose some useful methods of the util.ts module as `tree._util`. */
            this._util = util;
            // --- SELECT ---
            // /** @internal */
            // public selectRangeAnchor: WunderbaumNode | null = null;
            // --- FILTER ---
            this.filterMode = null;
            // --- KEYNAV ---
            /** @internal Use `setColumn()`/`getActiveColElem()` to access. */
            this.activeColIdx = 0;
            /** @internal */
            this._cellNavMode = false;
            /** @internal */
            this.lastQuicksearchTime = 0;
            /** @internal */
            this.lastQuicksearchTerm = "";
            // --- EDIT ---
            this.lastClickTime = 0;
            const opts = (this.options = extend({
                id: null,
                source: null,
                element: null,
                debugLevel: DEFAULT_DEBUGLEVEL,
                header: null,
                // headerHeightPx: ROW_HEIGHT,
                rowHeightPx: ROW_HEIGHT,
                iconMap: "bootstrap",
                columns: null,
                types: null,
                // escapeTitles: true,
                enabled: true,
                fixedCol: false,
                showSpinner: false,
                checkbox: false,
                minExpandLevel: 0,
                emptyChildListExpandable: false,
                // updateThrottleWait: 200,
                skeleton: false,
                connectTopBreadcrumb: null,
                selectMode: "multi",
                // --- KeyNav ---
                navigationModeOption: null,
                quicksearch: true,
                // --- Events ---
                iconBadge: null,
                change: null,
                // enhanceTitle: null,
                error: null,
                receive: null,
                // --- Strings ---
                strings: {
                    loadError: "Error",
                    loading: "Loading...",
                    // loading: "Loading&hellip;",
                    noData: "No data",
                },
            }, options));
            const readyDeferred = new Deferred();
            this.ready = readyDeferred.promise();
            let readyOk = false;
            this.ready
                .then(() => {
                readyOk = true;
                try {
                    this._callEvent("init");
                }
                catch (error) {
                    // We re-raise in the reject handler, but Chrome resets the stack
                    // frame then, so we log it here:
                    this.logError("Exception inside `init(e)` event:", error);
                }
            })
                .catch((err) => {
                if (readyOk) {
                    // Error occurred in `init` handler. We can re-raise, but Chrome
                    // resets the stack frame.
                    throw err;
                }
                else {
                    // Error in load process
                    this._callEvent("init", { error: err });
                }
            });
            this.id = opts.id || "wb_" + ++Wunderbaum.sequence;
            this.root = new WbSystemRoot(this);
            this._registerExtension(new KeynavExtension(this));
            this._registerExtension(new EditExtension(this));
            this._registerExtension(new FilterExtension(this));
            this._registerExtension(new DndExtension(this));
            this._registerExtension(new GridExtension(this));
            this._registerExtension(new LoggerExtension(this));
            this._updateViewportThrottled = adaptiveThrottle(this._updateViewportImmediately.bind(this), {});
            // --- Evaluate options
            this.columns = opts.columns;
            delete opts.columns;
            if (!this.columns || !this.columns.length) {
                const title = typeof opts.header === "string" ? opts.header : this.id;
                this.columns = [{ id: "*", title: title, width: "*" }];
            }
            if (opts.types) {
                this.setTypes(opts.types, true);
            }
            delete opts.types;
            // --- Create Markup
            this.element = elemFromSelector(opts.element);
            assert(!!this.element, `Invalid 'element' option: ${opts.element}`);
            this.element.classList.add("wunderbaum");
            if (!this.element.getAttribute("tabindex")) {
                this.element.tabIndex = 0;
            }
            // Attach tree instance to <div>
            this.element._wb_tree = this;
            // Create header markup, or take it from the existing html
            this.headerElement = this.element.querySelector("div.wb-header");
            const wantHeader = opts.header == null ? this.columns.length > 1 : !!opts.header;
            if (this.headerElement) {
                // User existing header markup to define `this.columns`
                assert(!this.columns, "`opts.columns` must not be set if markup already contains a header");
                this.columns = [];
                const rowElement = this.headerElement.querySelector("div.wb-row");
                for (const colDiv of rowElement.querySelectorAll("div")) {
                    this.columns.push({
                        id: colDiv.dataset.id || `col_${this.columns.length}`,
                        // id: colDiv.dataset.id || null,
                        title: "" + colDiv.textContent,
                        // text: "" + colDiv.textContent,
                        width: "*", // TODO: read from header span
                    });
                }
            }
            else {
                // We need a row div, the rest will be computed from `this.columns`
                const coldivs = "<span class='wb-col'></span>".repeat(this.columns.length);
                this.element.innerHTML = `
        <div class='wb-header'>
          <div class='wb-row'>
            ${coldivs}
          </div>
        </div>`;
                if (!wantHeader) {
                    const he = this.element.querySelector("div.wb-header");
                    he.style.display = "none";
                }
            }
            //
            this.element.innerHTML += `
      <div class="wb-list-container">
        <div class="wb-node-list"></div>
      </div>`;
            this.listContainerElement = this.element.querySelector("div.wb-list-container");
            this.nodeListElement = this.listContainerElement.querySelector("div.wb-node-list");
            this.headerElement = this.element.querySelector("div.wb-header");
            this.element.classList.toggle("wb-grid", this.columns.length > 1);
            this._initExtensions();
            // --- apply initial options
            ["enabled", "fixedCol"].forEach((optName) => {
                if (opts[optName] != null) {
                    this.setOption(optName, opts[optName]);
                }
            });
            // --- Load initial data
            if (opts.source) {
                if (opts.showSpinner) {
                    this.nodeListElement.innerHTML =
                        "<progress class='spinner'>loading...</progress>";
                }
                this.load(opts.source)
                    .then(() => {
                    // The source may have defined columns, so we may adjust the nav mode
                    if (opts.navigationModeOption == null) {
                        if (this.isGrid()) {
                            this.setNavigationOption(NavModeEnum.cell);
                        }
                        else {
                            this.setNavigationOption(NavModeEnum.row);
                        }
                    }
                    else {
                        this.setNavigationOption(opts.navigationModeOption);
                    }
                    this.update(ChangeType.structure, { immediate: true });
                    readyDeferred.resolve();
                })
                    .catch((error) => {
                    readyDeferred.reject(error);
                })
                    .finally(() => {
                    var _a;
                    (_a = this.element.querySelector("progress.spinner")) === null || _a === void 0 ? void 0 : _a.remove();
                    this.element.classList.remove("wb-initializing");
                });
            }
            else {
                readyDeferred.resolve();
            }
            // Async mode is sometimes required, because this.element.clientWidth
            // has a wrong value at start???
            this.update(ChangeType.any);
            // --- Bind listeners
            this.element.addEventListener("scroll", (e) => {
                // this.log(`scroll, scrollTop:${e.target.scrollTop}`, e);
                this.update(ChangeType.scroll);
            });
            this.resizeObserver = new ResizeObserver((entries) => {
                // this.log("ResizeObserver: Size changed", entries);
                this.update(ChangeType.resize);
            });
            this.resizeObserver.observe(this.element);
            onEvent(this.nodeListElement, "click", "div.wb-row", (e) => {
                const info = Wunderbaum.getEventInfo(e);
                const node = info.node;
                const mouseEvent = e;
                // this.log("click", info);
                // if (this._selectRange(info) === false) {
                //   return;
                // }
                if (this._callEvent("click", { event: e, node: node, info: info }) === false) {
                    this.lastClickTime = Date.now();
                    return false;
                }
                if (node) {
                    if (mouseEvent.ctrlKey) {
                        node.toggleSelected();
                        return;
                    }
                    // Edit title if 'clickActive' is triggered:
                    const trigger = this.getOption("edit.trigger");
                    const slowClickDelay = this.getOption("edit.slowClickDelay");
                    if (trigger.indexOf("clickActive") >= 0 &&
                        info.region === "title" &&
                        node.isActive() &&
                        (!slowClickDelay || Date.now() - this.lastClickTime < slowClickDelay)) {
                        node.startEditTitle();
                    }
                    if (info.colIdx >= 0) {
                        node.setActive(true, { colIdx: info.colIdx, event: e });
                    }
                    else {
                        node.setActive(true, { event: e });
                    }
                    if (info.region === NodeRegion.expander) {
                        node.setExpanded(!node.isExpanded(), {
                            scrollIntoView: options.scrollIntoViewOnExpandClick !== false,
                        });
                    }
                    else if (info.region === NodeRegion.checkbox) {
                        node.toggleSelected();
                    }
                }
                this.lastClickTime = Date.now();
            });
            onEvent(this.nodeListElement, "dblclick", "div.wb-row", (e) => {
                const info = Wunderbaum.getEventInfo(e);
                const node = info.node;
                // this.log("dblclick", info, e);
                if (this._callEvent("dblclick", { event: e, node: node, info: info }) ===
                    false) {
                    return false;
                }
                if (node && info.colIdx === 0 && node.isExpandable()) {
                    this._callMethod("edit._stopEditTitle");
                    node.setExpanded(!node.isExpanded());
                }
            });
            onEvent(this.element, "keydown", (e) => {
                const info = Wunderbaum.getEventInfo(e);
                const eventName = eventToString(e);
                const node = info.node || this.getFocusNode();
                this._callHook("onKeyEvent", {
                    event: e,
                    node: node,
                    info: info,
                    eventName: eventName,
                });
            });
            onEvent(this.element, "focusin focusout", (e) => {
                const flag = e.type === "focusin";
                const targetNode = Wunderbaum.getNode(e);
                this._callEvent("focus", { flag: flag, event: e });
                if (flag && this.isRowNav() && !this.isEditingTitle()) {
                    if (opts.navigationModeOption === NavModeEnum.row) {
                        targetNode === null || targetNode === void 0 ? void 0 : targetNode.setActive();
                    }
                    else {
                        this.setCellNav();
                    }
                }
                if (!flag) {
                    this._callMethod("edit._stopEditTitle", true, {
                        event: e,
                        forceClose: true,
                    });
                }
            });
        }
        /**
         * Return a Wunderbaum instance, from element, id, index, or event.
         *
         * ```js
         * getTree();         // Get first Wunderbaum instance on page
         * getTree(1);        // Get second Wunderbaum instance on page
         * getTree(event);    // Get tree for this mouse- or keyboard event
         * getTree("foo");    // Get tree for this `tree.options.id`
         * getTree("#tree");  // Get tree for first matching element selector
         * ```
         */
        static getTree(el) {
            if (el instanceof Wunderbaum) {
                return el;
            }
            else if (el instanceof WunderbaumNode) {
                return el.tree;
            }
            if (el === undefined) {
                el = 0; // get first tree
            }
            if (typeof el === "number") {
                el = document.querySelectorAll(".wunderbaum")[el]; // el was an integer: return nth element
            }
            else if (typeof el === "string") {
                // Search all trees for matching ID
                for (const treeElem of document.querySelectorAll(".wunderbaum")) {
                    const tree = treeElem._wb_tree;
                    if (tree && tree.id === el) {
                        return tree;
                    }
                }
                // Search by selector
                el = document.querySelector(el);
                if (!el) {
                    return null;
                }
            }
            else if (el.target) {
                el = el.target;
            }
            assert(el instanceof Element, `Invalid el type: ${el}`);
            if (!el.matches(".wunderbaum")) {
                el = el.closest(".wunderbaum");
            }
            if (el && el._wb_tree) {
                return el._wb_tree;
            }
            return null;
        }
        /**
         * Return the icon-function -> icon-definition mapping.
         */
        get iconMap() {
            const map = this.options.iconMap;
            if (typeof map === "string") {
                return iconMaps[map];
            }
            return map;
        }
        /**
         * Return a WunderbaumNode instance from element or event.
         */
        static getNode(el) {
            if (!el) {
                return null;
            }
            else if (el instanceof WunderbaumNode) {
                return el;
            }
            else if (el.target !== undefined) {
                el = el.target; // el was an Event
            }
            // `el` is a DOM element
            // let nodeElem = obj.closest("div.wb-row");
            while (el) {
                if (el._wb_node) {
                    return el._wb_node;
                }
                el = el.parentElement; //.parentNode;
            }
            return null;
        }
        /**
         * Iterate all descendant nodes depth-first, pre-order using `for ... of ...` syntax.
         * More concise, but slightly slower than {@link Wunderbaum.visit}.
         *
         * Example:
         * ```js
         * for(const node of tree) {
         *   ...
         * }
         * ```
         */
        *[Symbol.iterator]() {
            yield* this.root;
        }
        /** @internal */
        _registerExtension(extension) {
            this.extensionList.push(extension);
            this.extensions[extension.id] = extension;
            // this.extensionMap.set(extension.id, extension);
        }
        /** Called on tree (re)init after markup is created, before loading. */
        _initExtensions() {
            for (const ext of this.extensionList) {
                ext.init();
            }
        }
        /** Add node to tree's bookkeeping data structures. */
        _registerNode(node) {
            const key = node.key;
            assert(key != null, `Missing key: '${node}'.`);
            assert(!this.keyMap.has(key), `Duplicate key: '${key}': ${node}.`);
            this.keyMap.set(key, node);
            const rk = node.refKey;
            if (rk != null) {
                const rks = this.refKeyMap.get(rk); // Set of nodes with this refKey
                if (rks) {
                    rks.add(node);
                }
                else {
                    this.refKeyMap.set(rk, new Set([node]));
                }
            }
        }
        /** Remove node from tree's bookkeeping data structures. */
        _unregisterNode(node) {
            // Remove refKey reference from map (if any)
            const rk = node.refKey;
            if (rk != null) {
                const rks = this.refKeyMap.get(rk);
                if (rks && rks.delete(node) && !rks.size) {
                    // We just removed the last element
                    this.refKeyMap.delete(rk);
                }
            }
            // Remove key reference from map
            this.keyMap.delete(node.key);
            // Mark as disposed
            node.tree = null;
            node.parent = null;
            // Remove HTML markup
            node.removeMarkup();
        }
        /** Call all hook methods of all registered extensions.*/
        _callHook(hook, data = {}) {
            let res;
            const d = extend({}, { tree: this, options: this.options, result: undefined }, data);
            for (const ext of this.extensionList) {
                res = ext[hook].call(ext, d);
                if (res === false) {
                    break;
                }
                if (d.result !== undefined) {
                    res = d.result;
                }
            }
            return res;
        }
        /**
         * Call tree method or extension method if defined.
         *
         * Example:
         * ```js
         * tree._callMethod("edit.startEdit", "arg1", "arg2")
         * ```
         */
        _callMethod(name, ...args) {
            const [p, n] = name.split(".");
            const obj = n ? this.extensions[p] : this;
            const func = obj[n];
            if (func) {
                return func.apply(obj, args);
            }
            else {
                this.logError(`Calling undefined method '${name}()'.`);
            }
        }
        /**
         * Call event handler if defined in tree or tree.EXTENSION options.
         *
         * Example:
         * ```js
         * tree._callEvent("edit.beforeEdit", {foo: 42})
         * ```
         */
        _callEvent(type, extra) {
            const [p, n] = type.split(".");
            const opts = this.options;
            const func = n ? opts[p][n] : opts[p];
            if (func) {
                return func.call(this, extend({ type: type, tree: this, util: this._util }, extra));
                // } else {
                //   this.logError(`Triggering undefined event '${type}'.`)
            }
        }
        /** Return the node for  given row index. */
        _getNodeByRowIdx(idx) {
            // TODO: start searching from active node (reverse)
            let node = null;
            this.visitRows((n) => {
                if (n._rowIdx === idx) {
                    node = n;
                    return false;
                }
            });
            return node;
        }
        /** Return the topmost visible node in the viewport. */
        getTopmostVpNode(complete = true) {
            const gracePx = 1; // ignore subpixel scrolling
            const scrollParent = this.element;
            // const headerHeight = this.headerElement.clientHeight;  // May be 0
            const scrollTop = scrollParent.scrollTop; // + headerHeight;
            let topIdx;
            if (complete) {
                topIdx = Math.ceil((scrollTop - gracePx) / ROW_HEIGHT);
            }
            else {
                topIdx = Math.floor(scrollTop / ROW_HEIGHT);
            }
            return this._getNodeByRowIdx(topIdx);
        }
        /** Return the lowest visible node in the viewport. */
        getLowestVpNode(complete = true) {
            const scrollParent = this.element;
            const headerHeight = this.headerElement.clientHeight; // May be 0
            const scrollTop = scrollParent.scrollTop;
            const clientHeight = scrollParent.clientHeight - headerHeight;
            let bottomIdx;
            if (complete) {
                bottomIdx = Math.floor((scrollTop + clientHeight) / ROW_HEIGHT) - 1;
            }
            else {
                bottomIdx = Math.ceil((scrollTop + clientHeight) / ROW_HEIGHT) - 1;
            }
            bottomIdx = Math.min(bottomIdx, this.count(true) - 1);
            return this._getNodeByRowIdx(bottomIdx);
        }
        /** Return preceeding visible node in the viewport. */
        _getPrevNodeInView(node, ofs = 1) {
            this.visitRows((n) => {
                node = n;
                if (ofs-- <= 0) {
                    return false;
                }
            }, { reverse: true, start: node || this.getActiveNode() });
            return node;
        }
        /** Return following visible node in the viewport. */
        _getNextNodeInView(node, ofs = 1) {
            this.visitRows((n) => {
                node = n;
                if (ofs-- <= 0) {
                    return false;
                }
            }, { reverse: false, start: node || this.getActiveNode() });
            return node;
        }
        /**
         * Append (or insert) a list of toplevel nodes.
         *
         * @see {@link WunderbaumNode.addChildren}
         */
        addChildren(nodeData, options) {
            return this.root.addChildren(nodeData, options);
        }
        /**
         * Apply a modification or navigation operation.
         *
         * Most of these commands simply map to a node or tree method.
         * This method is especially useful when implementing keyboard mapping,
         * context menus, or external buttons.
         *
         * Valid commands:
         *   - 'moveUp', 'moveDown'
         *   - 'indent', 'outdent'
         *   - 'remove'
         *   - 'edit', 'addChild', 'addSibling': (reqires ext-edit extension)
         *   - 'cut', 'copy', 'paste': (use an internal singleton 'clipboard')
         *   - 'down', 'first', 'last', 'left', 'parent', 'right', 'up': navigate
         *
         */
        applyCommand(cmd, nodeOrOpts, options) {
            let // clipboard,
            node, refNode;
            // options = $.extend(
            // 	{ setActive: true, clipboard: CLIPBOARD },
            // 	options_
            // );
            if (nodeOrOpts instanceof WunderbaumNode) {
                node = nodeOrOpts;
            }
            else {
                node = this.getActiveNode();
                assert(options === undefined, `Unexpected options: ${options}`);
                options = nodeOrOpts;
            }
            // clipboard = options.clipboard;
            switch (cmd) {
                // Sorting and indentation:
                case "moveUp":
                    refNode = node.getPrevSibling();
                    if (refNode) {
                        node.moveTo(refNode, "before");
                        node.setActive();
                    }
                    break;
                case "moveDown":
                    refNode = node.getNextSibling();
                    if (refNode) {
                        node.moveTo(refNode, "after");
                        node.setActive();
                    }
                    break;
                case "indent":
                    refNode = node.getPrevSibling();
                    if (refNode) {
                        node.moveTo(refNode, "appendChild");
                        refNode.setExpanded();
                        node.setActive();
                    }
                    break;
                case "outdent":
                    if (!node.isTopLevel()) {
                        node.moveTo(node.getParent(), "after");
                        node.setActive();
                    }
                    break;
                // Remove:
                case "remove":
                    refNode = node.getPrevSibling() || node.getParent();
                    node.remove();
                    if (refNode) {
                        refNode.setActive();
                    }
                    break;
                // Add, edit (requires ext-edit):
                case "addChild":
                    this._callMethod("edit.createNode", "prependChild");
                    break;
                case "addSibling":
                    this._callMethod("edit.createNode", "after");
                    break;
                case "rename":
                    node.startEditTitle();
                    break;
                // Simple clipboard simulation:
                // case "cut":
                // 	clipboard = { mode: cmd, data: node };
                // 	break;
                // case "copy":
                // 	clipboard = {
                // 		mode: cmd,
                // 		data: node.toDict(function(d, n) {
                // 			delete d.key;
                // 		}),
                // 	};
                // 	break;
                // case "clear":
                // 	clipboard = null;
                // 	break;
                // case "paste":
                // 	if (clipboard.mode === "cut") {
                // 		// refNode = node.getPrevSibling();
                // 		clipboard.data.moveTo(node, "child");
                // 		clipboard.data.setActive();
                // 	} else if (clipboard.mode === "copy") {
                // 		node.addChildren(clipboard.data).setActive();
                // 	}
                // 	break;
                // Navigation commands:
                case "down":
                case "first":
                case "last":
                case "left":
                case "pageDown":
                case "pageUp":
                case "parent":
                case "right":
                case "up":
                    return node.navigate(cmd);
                default:
                    error(`Unhandled command: '${cmd}'`);
            }
        }
        /** Delete all nodes. */
        clear() {
            this.root.removeChildren();
            this.root.children = null;
            this.keyMap.clear();
            this.refKeyMap.clear();
            this.treeRowCount = 0;
            this._activeNode = null;
            this._focusNode = null;
            // this.types = {};
            // this. columns =[];
            // this._columnsById = {};
            // Modification Status
            // this.changedSince = 0;
            // this.changes.clear();
            // this.changedNodes.clear();
            // // --- FILTER ---
            // public filterMode: FilterModeType = null;
            // // --- KEYNAV ---
            // public activeColIdx = 0;
            // public cellNavMode = false;
            // public lastQuicksearchTime = 0;
            // public lastQuicksearchTerm = "";
            this.update(ChangeType.structure);
        }
        /**
         * Clear nodes and markup and detach events and observers.
         *
         * This method may be useful to free up resources before re-creating a tree
         * on an existing div, for example in unittest suites.
         * Note that this Wunderbaum instance becomes unusable afterwards.
         */
        destroy() {
            this.logInfo("destroy()...");
            this.clear();
            this.resizeObserver.disconnect();
            this.element.innerHTML = "";
            // Remove all event handlers
            this.element.outerHTML = this.element.outerHTML; // eslint-disable-line
        }
        /**
         * Return `tree.option.NAME` (also resolving if this is a callback).
         *
         * See also {@link WunderbaumNode.getOption|WunderbaumNode.getOption()}
         * to evaluate `node.NAME` setting and `tree.types[node.type].NAME`.
         *
         * @param name option name (use dot notation to access extension option, e.g.
         * `filter.mode`)
         */
        getOption(name, defaultValue) {
            let ext;
            let opts = this.options;
            // Lookup `name` in options dict
            if (name.indexOf(".") >= 0) {
                [ext, name] = name.split(".");
                opts = opts[ext];
            }
            let value = opts[name];
            // A callback resolver always takes precedence
            if (typeof value === "function") {
                value = value({ type: "resolve", tree: this });
            }
            // Use value from value options dict, fallback do default
            // console.info(name, value, opts)
            return value !== null && value !== void 0 ? value : defaultValue;
        }
        /**
         * Set tree option.
         * Use dot notation to set plugin option, e.g. "filter.mode".
         */
        setOption(name, value) {
            // this.log(`setOption(${name}, ${value})`);
            if (name.indexOf(".") >= 0) {
                const parts = name.split(".");
                const ext = this.extensions[parts[0]];
                ext.setPluginOption(parts[1], value);
                return;
            }
            this.options[name] = value;
            switch (name) {
                case "checkbox":
                    this.update(ChangeType.any);
                    break;
                case "enabled":
                    this.setEnabled(!!value);
                    break;
                case "fixedCol":
                    this.element.classList.toggle("wb-fixed-col", !!value);
                    break;
            }
        }
        /** Return true if the tree (or one of its nodes) has the input focus. */
        hasFocus() {
            return this.element.contains(document.activeElement);
        }
        /**
         * Return true if the tree displays a header. Grids have a header unless the
         * `header` option is set to `false`. Plain trees have a header if the `header`
         * option is a string or `true`.
         */
        hasHeader() {
            const header = this.options.header;
            return this.isGrid() ? header !== false : !!header;
        }
        /** Run code, but defer rendering of viewport until done.
         *
         * ```
         * tree.runWithDeferredUpdate(() => {
         *   return someFuncThatWouldUpdateManyNodes();
         * });
         * ```
         */
        runWithDeferredUpdate(func, hint = null) {
            try {
                this.enableUpdate(false);
                const res = func();
                assert(!(res instanceof Promise), `Promise return not allowed: ${res}`);
                return res;
            }
            finally {
                this.enableUpdate(true);
            }
        }
        /** Recursively expand all expandable nodes (triggers lazy load if needed). */
        async expandAll(flag = true, options) {
            await this.root.expandAll(flag, options);
        }
        /** Recursively select all nodes. */
        selectAll(flag = true) {
            return this.root.setSelected(flag, { propagateDown: true });
        }
        /** Toggle select all nodes. */
        toggleSelect() {
            this.selectAll(this.root._anySelectable());
        }
        /**
         * Return an array of selected nodes.
         * @param stopOnParents only return the topmost selected node (useful with selectMode 'hier')
         */
        getSelectedNodes(stopOnParents = false) {
            return this.root.getSelectedNodes(stopOnParents);
        }
        /*
         * Return an array of selected nodes.
         */
        _selectRange(eventInfo) {
            this.logDebug("_selectRange", eventInfo);
            error("Not yet implemented.");
            // const mode = this.options.selectMode!;
            // if (mode !== "multi") {
            //   this.logDebug(`Range selection only available for selectMode 'multi'`);
            //   return;
            // }
            // if (eventInfo.canonicalName === "Meta+click") {
            //   eventInfo.node?.toggleSelected();
            //   return false; // don't
            // } else if (eventInfo.canonicalName === "Shift+click") {
            //   let from = this.activeNode;
            //   let to = eventInfo.node;
            //   if (!from || !to || from === to) {
            //     return;
            //   }
            //   this.runWithDeferredUpdate(() => {
            //     this.visitRows(
            //       (node) => {
            //         node.setSelected();
            //       },
            //       {
            //         includeHidden: true,
            //         includeSelf: false,
            //         start: from,
            //         reverse: from!._rowIdx! > to!._rowIdx!,
            //       }
            //     );
            //   });
            //   return false;
            // }
        }
        /** Return the number of nodes in the data model.
         * @param visible if true, nodes that are hidden due to collapsed parents are ignored.
         */
        count(visible = false) {
            return visible ? this.treeRowCount : this.keyMap.size;
        }
        /** @internal sanity check. */
        _check() {
            let i = 0;
            this.visit((n) => {
                i++;
            });
            if (this.keyMap.size !== i) {
                this.logWarn(`_check failed: ${this.keyMap.size} !== ${i}`);
            }
            // util.assert(this.keyMap.size === i);
        }
        /**
         * Find all nodes that match condition.
         *
         * @param match title string to search for, or a
         *     callback function that returns `true` if a node is matched.
         * @see {@link WunderbaumNode.findAll}
         */
        findAll(match) {
            return this.root.findAll(match);
        }
        /**
         * Find all nodes with a given _refKey_ (aka a list of clones).
         *
         * @param refKey a `node.refKey` value to search for.
         * @returns an array of matching nodes with at least two element or `[]`
         * if nothing found.
         *
         * @see {@link WunderbaumNode.getCloneList}
         */
        findByRefKey(refKey) {
            const clones = this.refKeyMap.get(refKey);
            return clones ? Array.from(clones) : [];
        }
        /**
         * Find first node that matches condition.
         *
         * @param match title string to search for, or a
         *     callback function that returns `true` if a node is matched.
         * @see {@link WunderbaumNode.findFirst}
         */
        findFirst(match) {
            return this.root.findFirst(match);
        }
        /**
         * Find first node that matches condition.
         *
         * @see {@link WunderbaumNode.findFirst}
         *
         */
        findKey(key) {
            return this.keyMap.get(key) || null;
        }
        /**
         * Find the next visible node that starts with `match`, starting at `startNode`
         * and wrap-around at the end.
         * Used by quicksearch and keyboard navigation.
         */
        findNextNode(match, startNode) {
            //, visibleOnly) {
            let res = null;
            const firstNode = this.getFirstChild();
            const matcher = typeof match === "string" ? makeNodeTitleStartMatcher(match) : match;
            startNode = startNode || firstNode;
            function _checkNode(n) {
                // console.log("_check " + n)
                if (matcher(n)) {
                    res = n;
                }
                if (res || n === startNode) {
                    return false;
                }
            }
            this.visitRows(_checkNode, {
                start: startNode,
                includeSelf: false,
            });
            // Wrap around search
            if (!res && startNode !== firstNode) {
                this.visitRows(_checkNode, {
                    start: firstNode,
                    includeSelf: true,
                });
            }
            return res;
        }
        /**
         * Find a node relative to another node.
         *
         * @param node
         * @param where 'down', 'first', 'last', 'left', 'parent', 'right', or 'up'.
         *   (Alternatively the keyCode that would normally trigger this move,
         *   e.g. `$.ui.keyCode.LEFT` = 'left'.
         * @param includeHidden Not yet implemented
         */
        findRelatedNode(node, where, includeHidden = false) {
            let res = null;
            const pageSize = Math.floor(this.listContainerElement.clientHeight / ROW_HEIGHT);
            switch (where) {
                case "parent":
                    if (node.parent && node.parent.parent) {
                        res = node.parent;
                    }
                    break;
                case "first":
                    // First visible node
                    this.visit((n) => {
                        if (n.isVisible()) {
                            res = n;
                            return false;
                        }
                    });
                    break;
                case "last":
                    this.visit((n) => {
                        // last visible node
                        if (n.isVisible()) {
                            res = n;
                        }
                    });
                    break;
                case "left":
                    if (node.parent && node.parent.parent) {
                        res = node.parent;
                    }
                    // if (node.expanded) {
                    //   node.setExpanded(false);
                    // } else if (node.parent && node.parent.parent) {
                    //   res = node.parent;
                    // }
                    break;
                case "right":
                    if (node.children && node.children.length) {
                        res = node.children[0];
                    }
                    // if (this.cellNavMode) {
                    //   throw new Error("Not implemented");
                    // } else {
                    //   if (!node.expanded && (node.children || node.lazy)) {
                    //     node.setExpanded();
                    //     res = node;
                    //   } else if (node.children && node.children.length) {
                    //     res = node.children[0];
                    //   }
                    // }
                    break;
                case "up":
                    res = this._getPrevNodeInView(node);
                    break;
                case "down":
                    res = this._getNextNodeInView(node);
                    break;
                case "pageDown":
                    {
                        const bottomNode = this.getLowestVpNode();
                        // this.logDebug(`${where}(${node}) -> ${bottomNode}`);
                        if (node._rowIdx < bottomNode._rowIdx) {
                            res = bottomNode;
                        }
                        else {
                            res = this._getNextNodeInView(node, pageSize);
                        }
                    }
                    break;
                case "pageUp":
                    if (node._rowIdx === 0) {
                        res = node;
                    }
                    else {
                        const topNode = this.getTopmostVpNode();
                        // this.logDebug(`${where}(${node}) -> ${topNode}`);
                        if (node._rowIdx > topNode._rowIdx) {
                            res = topNode;
                        }
                        else {
                            res = this._getPrevNodeInView(node, pageSize);
                        }
                    }
                    break;
                default:
                    this.logWarn("Unknown relation '" + where + "'.");
            }
            return res;
        }
        /**
         * Iterator version of {@link Wunderbaum.format}.
         */
        *format_iter(name_cb, connectors) {
            yield* this.root.format_iter(name_cb, connectors);
        }
        /**
         * Return multiline string representation of the node hierarchy.
         * Mostly useful for debugging.
         *
         * Example:
         * ```js
         * console.info(tree.format((n)=>n.title));
         * ```
         * logs
         * ```
         * Playground
         * ├─ Books
         * |   ├─ Art of War
         * |   ╰─ Don Quixote
         * ├─ Music
         * ...
         * ```
         *
         * @see {@link Wunderbaum.format_iter} and {@link WunderbaumNode.format}.
         */
        format(name_cb, connectors) {
            return this.root.format(name_cb, connectors);
        }
        /**
         * Return the active cell (`span.wb-col`) of the currently active node or null.
         */
        getActiveColElem() {
            if (this.activeNode && this.activeColIdx >= 0) {
                return this.activeNode.getColElem(this.activeColIdx);
            }
            return null;
        }
        /**
         * Return the currently active node or null (alias for `tree.activeNode`).
         * Alias for {@link Wunderbaum.activeNode}.
         *
         * @see {@link WunderbaumNode.setActive}
         * @see {@link WunderbaumNode.isActive}
         * @see {@link Wunderbaum.activeNode}
         * @see {@link Wunderbaum.focusNode}
         */
        getActiveNode() {
            return this.activeNode;
        }
        /**
         * Return the first top level node if any (not the invisible root node).
         */
        getFirstChild() {
            return this.root.getFirstChild();
        }
        /**
         * Return the node that currently has keyboard focus or null.
         * Alias for {@link Wunderbaum.focusNode}.
         * @see {@link WunderbaumNode.setFocus}
         * @see {@link WunderbaumNode.hasFocus}
         * @see {@link Wunderbaum.activeNode}
         * @see {@link Wunderbaum.focusNode}
         */
        getFocusNode() {
            return this.focusNode;
        }
        /** Return a {node: WunderbaumNode, region: TYPE} object for a mouse event.
         *
         * @param {Event} event Mouse event, e.g. click, ...
         * @returns {object} Return a {node: WunderbaumNode, region: TYPE} object
         *     TYPE: 'title' | 'prefix' | 'expander' | 'checkbox' | 'icon' | undefined
         */
        static getEventInfo(event) {
            const target = event.target;
            const cl = target.classList;
            const parentCol = target.closest("span.wb-col");
            const node = Wunderbaum.getNode(target);
            const tree = node ? node.tree : Wunderbaum.getTree(event);
            const res = {
                event: event,
                canonicalName: eventToString(event),
                tree: tree,
                node: node,
                region: NodeRegion.unknown,
                colDef: undefined,
                colIdx: -1,
                colId: undefined,
                colElem: parentCol,
            };
            if (cl.contains("wb-title")) {
                res.region = NodeRegion.title;
            }
            else if (cl.contains("wb-expander")) {
                res.region = node.isExpandable()
                    ? NodeRegion.expander
                    : NodeRegion.prefix;
            }
            else if (cl.contains("wb-checkbox")) {
                res.region = NodeRegion.checkbox;
            }
            else if (cl.contains("wb-icon")) {
                //|| cl.contains("wb-custom-icon")) {
                res.region = NodeRegion.icon;
            }
            else if (cl.contains("wb-node")) {
                res.region = NodeRegion.title;
            }
            else if (parentCol) {
                res.region = NodeRegion.column;
                const idx = Array.prototype.indexOf.call(parentCol.parentNode.children, parentCol);
                res.colIdx = idx;
            }
            else if (cl.contains("wb-row")) {
                // Plain tree
                res.region = NodeRegion.title;
            }
            else {
                // Somewhere near the title
                if (event.type !== "mousemove" && !(event instanceof KeyboardEvent)) {
                    tree === null || tree === void 0 ? void 0 : tree.logWarn("getEventInfo(): not found", event, res);
                }
                return res;
            }
            if (res.colIdx === -1) {
                res.colIdx = 0;
            }
            res.colDef = tree === null || tree === void 0 ? void 0 : tree.columns[res.colIdx];
            res.colDef != null ? (res.colId = res.colDef.id) : 0;
            // this.log("Event", event, res);
            return res;
        }
        /**
         * Return readable string representation for this instance.
         * @internal
         */
        toString() {
            return `Wunderbaum<'${this.id}'>`;
        }
        /** Return true if any node title or grid cell is currently beeing edited.
         *
         * See also {@link Wunderbaum.isEditingTitle}.
         */
        isEditing() {
            const focusElem = this.nodeListElement.querySelector("input:focus,select:focus");
            return !!focusElem;
        }
        /** Return true if any node is currently in edit-title mode.
         *
         * See also {@link WunderbaumNode.isEditingTitle} and {@link Wunderbaum.isEditing}.
         */
        isEditingTitle() {
            return this._callMethod("edit.isEditingTitle");
        }
        /**
         * Return true if any node is currently beeing loaded, i.e. a Ajax request is pending.
         */
        isLoading() {
            let res = false;
            this.root.visit((n) => {
                // also visit rootNode
                if (n._isLoading || n._requestId) {
                    res = true;
                    return false;
                }
            }, true);
            return res;
        }
        /** Write to `console.log` with tree name as prefix if opts.debugLevel >= 4.
         * @see {@link Wunderbaum.logDebug}
         */
        log(...args) {
            if (this.options.debugLevel >= 4) {
                console.log(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.debug`  with tree name as prefix if opts.debugLevel >= 4.
         * and browser console level includes debug/verbose messages.
         * @see {@link Wunderbaum.log}
         */
        logDebug(...args) {
            if (this.options.debugLevel >= 4) {
                console.debug(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.error` with tree name as prefix. */
        logError(...args) {
            if (this.options.debugLevel >= 1) {
                console.error(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** Write to `console.info`  with tree name as prefix if opts.debugLevel >= 3. */
        logInfo(...args) {
            if (this.options.debugLevel >= 3) {
                console.info(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /** @internal */
        logTime(label) {
            if (this.options.debugLevel >= 4) {
                console.time(this + ": " + label); // eslint-disable-line no-console
            }
            return label;
        }
        /** @internal */
        logTimeEnd(label) {
            if (this.options.debugLevel >= 4) {
                console.timeEnd(this + ": " + label); // eslint-disable-line no-console
            }
        }
        /** Write to `console.warn` with tree name as prefix with if opts.debugLevel >= 2. */
        logWarn(...args) {
            if (this.options.debugLevel >= 2) {
                console.warn(this.toString(), ...args); // eslint-disable-line no-console
            }
        }
        /**
         * Make sure that this node is vertically scrolled into the viewport.
         *
         * Nodes that are above the visible area become the top row, nodes that are
         * below the viewport become the bottom row.
         */
        scrollTo(nodeOrOpts) {
            const PADDING = 2; // leave some pixels between viewport bounds
            let node;
            let options;
            if (nodeOrOpts instanceof WunderbaumNode) {
                node = nodeOrOpts;
            }
            else {
                options = nodeOrOpts;
                node = options.node;
            }
            assert(node && node._rowIdx != null, `Invalid node: ${node}`);
            const scrollParent = this.element;
            const headerHeight = this.headerElement.clientHeight; // May be 0
            const scrollTop = scrollParent.scrollTop;
            const vpHeight = scrollParent.clientHeight;
            const rowTop = node._rowIdx * ROW_HEIGHT + headerHeight;
            const vpTop = headerHeight;
            const vpRowTop = rowTop - scrollTop;
            const vpRowBottom = vpRowTop + ROW_HEIGHT;
            const topNode = options === null || options === void 0 ? void 0 : options.topNode;
            // this.log( `scrollTo(${node.title}), vpTop:${vpTop}px, scrollTop:${scrollTop}, vpHeight:${vpHeight}, rowTop:${rowTop}, vpRowTop:${vpRowTop}`, nodeOrOpts , options);
            let newScrollTop = null;
            if (vpRowTop >= vpTop) {
                if (vpRowBottom <= vpHeight) ;
                else {
                    // Node is below viewport
                    // this.log("Below viewport");
                    newScrollTop = rowTop + ROW_HEIGHT - vpHeight + PADDING; // leave some pixels between viewport bounds
                }
            }
            else {
                // Node is above viewport
                // this.log("Above viewport");
                newScrollTop = rowTop - vpTop - PADDING; // leave some pixels between viewport bounds
            }
            if (newScrollTop != null) {
                this.log(`scrollTo(${rowTop}): ${scrollTop} => ${newScrollTop}`);
                scrollParent.scrollTop = newScrollTop;
                if (topNode) {
                    // Make sure the topNode is always visible
                    this.scrollTo(topNode);
                }
                // this.update(ChangeType.scroll);
            }
        }
        /**
         * Make sure that this node is horizontally scrolled into the viewport.
         * Called by {@link setColumn}.
         */
        scrollToHorz() {
            // const PADDING = 1;
            const fixedWidth = this.columns[0]._widthPx;
            const vpWidth = this.element.clientWidth;
            const scrollLeft = this.element.scrollLeft;
            const colElem = this.getActiveColElem();
            const colLeft = Number.parseInt(colElem === null || colElem === void 0 ? void 0 : colElem.style.left, 10);
            const colRight = colLeft + Number.parseInt(colElem === null || colElem === void 0 ? void 0 : colElem.style.width, 10);
            let newLeft = scrollLeft;
            if (colLeft - scrollLeft < fixedWidth) {
                // The current column is scrolled behind the left fixed column
                newLeft = colLeft - fixedWidth;
            }
            else if (colRight - scrollLeft > vpWidth) {
                // The current column is scrolled outside the right side
                newLeft = colRight - vpWidth;
            }
            newLeft = Math.max(0, newLeft);
            // util.assert(node._rowIdx != null);
            this.log(`scrollToHorz(${this.activeColIdx}): ${colLeft}..${colRight}, fixedOfs=${fixedWidth}, vpWidth=${vpWidth}, curLeft=${scrollLeft} -> ${newLeft}`);
            this.element.scrollLeft = newLeft;
            // this.update(ChangeType.scroll);
        }
        /**
         * Set column #colIdx to 'active'.
         *
         * This higlights the column header and -cells by adding the `wb-active`
         * class to all grid cells of the active column. <br>
         * Available in cell-nav mode only.
         *
         * If _options.edit_ is true, the embedded input element is focused, or if
         * colIdx is 0, the node title is put into edit mode.
         */
        setColumn(colIdx, options) {
            var _a, _b, _c;
            const edit = options === null || options === void 0 ? void 0 : options.edit;
            const scroll = (options === null || options === void 0 ? void 0 : options.scrollIntoView) !== false;
            assert(this.isCellNav(), "Expected cellNav mode");
            if (typeof colIdx === "string") {
                const cid = colIdx;
                colIdx = this.columns.findIndex((c) => c.id === colIdx);
                assert(colIdx >= 0, `Invalid colId: ${cid}`);
            }
            assert(0 <= colIdx && colIdx < this.columns.length, `Invalid colIdx: ${colIdx}`);
            this.activeColIdx = colIdx;
            // Update `wb-active` class for all headers
            if (this.hasHeader()) {
                for (const rowDiv of this.headerElement.children) {
                    let i = 0;
                    for (const colDiv of rowDiv.children) {
                        colDiv.classList.toggle("wb-active", i++ === colIdx);
                    }
                }
            }
            (_a = this.activeNode) === null || _a === void 0 ? void 0 : _a.update(ChangeType.status);
            // Update `wb-active` class for all cell spans
            for (const rowDiv of this.nodeListElement.children) {
                let i = 0;
                for (const colDiv of rowDiv.children) {
                    colDiv.classList.toggle("wb-active", i++ === colIdx);
                }
            }
            // Horizontically scroll into view
            if (scroll || edit) {
                this.scrollToHorz();
            }
            if (edit && this.activeNode) {
                // this.activeNode.setFocus(); // Blur prev. input if any
                if (colIdx === 0) {
                    this.activeNode.startEditTitle();
                }
                else {
                    (_c = (_b = this.getActiveColElem()) === null || _b === void 0 ? void 0 : _b.querySelector("input,select")) === null || _c === void 0 ? void 0 : _c.focus();
                }
            }
        }
        /* Set or remove keyboard focus to the tree container. @internal */
        _setActiveNode(node) {
            this._activeNode = node;
        }
        /** Set or remove keyboard focus to the tree container. */
        setActiveNode(key, flag = true, options) {
            var _a;
            (_a = this.findKey(key)) === null || _a === void 0 ? void 0 : _a.setActive(flag, options);
        }
        /** Set or remove keyboard focus to the tree container. */
        setFocus(flag = true) {
            if (flag) {
                this.element.focus();
            }
            else {
                this.element.blur();
            }
        }
        /* Set or remove keyboard focus to the tree container. @internal */
        _setFocusNode(node) {
            this._focusNode = node;
        }
        update(change, node, options) {
            // this.log(`update(${change}) node=${node}`);
            if (!(node instanceof WunderbaumNode)) {
                options = node;
                node = undefined;
            }
            const immediate = !!getOption(options, "immediate");
            const RF = RenderFlag;
            const pending = this.pendingChangeTypes;
            if (this._disableUpdateCount) {
                // Assuming that we redraw all when enableUpdate() is re-enabled.
                // this.log(
                //   `IGNORED update(${change}) node=${node} (disable level ${this._disableUpdateCount})`
                // );
                this._disableUpdateIgnoreCount++;
                return;
            }
            switch (change) {
                case ChangeType.any:
                case ChangeType.colStructure:
                    pending.add(RF.header);
                    pending.add(RF.clearMarkup);
                    pending.add(RF.redraw);
                    pending.add(RF.scroll);
                    break;
                case ChangeType.resize:
                    // case ChangeType.colWidth:
                    pending.add(RF.header);
                    pending.add(RF.redraw);
                    break;
                case ChangeType.structure:
                    pending.add(RF.redraw);
                    break;
                case ChangeType.scroll:
                    pending.add(RF.scroll);
                    break;
                case ChangeType.row:
                case ChangeType.data:
                case ChangeType.status:
                    assert(node, `Option '${change}' requires a node.`);
                    // Single nodes are immediately updated if already inside the viewport
                    // (otherwise we can ignore)
                    if (node._rowElem) {
                        node._render({ change: change });
                    }
                    break;
                default:
                    error(`Invalid change type '${change}'.`);
            }
            if (change === ChangeType.colStructure) {
                const isGrid = this.isGrid();
                this.element.classList.toggle("wb-grid", isGrid);
                if (!isGrid && this.isCellNav()) {
                    this.setCellNav(false);
                }
            }
            if (pending.size > 0) {
                if (immediate) {
                    this._updateViewportImmediately();
                }
                else {
                    this._updateViewportThrottled();
                }
            }
        }
        /** Disable mouse and keyboard interaction (return prev. state). */
        setEnabled(flag = true) {
            const prev = this.enabled;
            this.enabled = !!flag;
            this.element.classList.toggle("wb-disabled", !flag);
            return prev;
        }
        /** Return false if tree is disabled. */
        isEnabled() {
            return this.enabled;
        }
        /** Return true if tree has more than one column, i.e. has additional data columns. */
        isGrid() {
            return this.columns && this.columns.length > 1;
        }
        /** Return true if cell-navigation mode is active. */
        isCellNav() {
            return !!this._cellNavMode;
        }
        /** Return true if row-navigation mode is active. */
        isRowNav() {
            return !this._cellNavMode;
        }
        /** Set the tree's navigation mode. */
        setCellNav(flag = true) {
            var _a;
            const prev = this._cellNavMode;
            // if (flag === prev) {
            //   return;
            // }
            this._cellNavMode = !!flag;
            if (flag && !prev) {
                // switch from row to cell mode
                this.setColumn(0);
            }
            this.element.classList.toggle("wb-cell-mode", flag);
            (_a = this.activeNode) === null || _a === void 0 ? void 0 : _a.update(ChangeType.status);
        }
        /** Set the tree's navigation mode option. */
        setNavigationOption(mode, reset = false) {
            if (!this.isGrid() && mode !== NavModeEnum.row) {
                this.logWarn("Plain trees only support row navigation mode.");
                return;
            }
            this.options.navigationModeOption = mode;
            switch (mode) {
                case NavModeEnum.cell:
                    this.setCellNav(true);
                    break;
                case NavModeEnum.row:
                    this.setCellNav(false);
                    break;
                case NavModeEnum.startCell:
                    if (reset) {
                        this.setCellNav(true);
                    }
                    break;
                case NavModeEnum.startRow:
                    if (reset) {
                        this.setCellNav(false);
                    }
                    break;
                default:
                    error(`Invalid mode '${mode}'.`);
            }
        }
        /** Display tree status (ok, loading, error, noData) using styles and a dummy root node. */
        setStatus(status, options) {
            return this.root.setStatus(status, options);
        }
        /** Add or redefine node type definitions. */
        setTypes(types, replace = true) {
            assert(isPlainObject(types), `Expected plain objext: ${types}`);
            if (replace) {
                this.types = types;
            }
            else {
                extend(this.types, types);
            }
            // Convert `TYPE.classes` to a Set
            for (const t of Object.values(this.types)) {
                if (t.classes) {
                    t.classes = toSet(t.classes);
                }
            }
        }
        /**
         * Sort nodes list by title or custom criteria.
         * @param {function} cmp custom compare function(a, b) that returns -1, 0, or 1
         *    (defaults to sorting by title).
         * @param {boolean} deep pass true to sort all descendant nodes recursively
         */
        sortChildren(cmp = nodeTitleSorter, deep = false) {
            this.root.sortChildren(cmp, deep);
        }
        /** Convert tree to an array of plain objects.
         *
         * @param callback(dict, node) is called for every node, in order to allow
         *     modifications.
         *     Return `false` to ignore this node or `"skip"` to include this node
         *     without its children.
         * @see {@link WunderbaumNode.toDict}.
         */
        toDictArray(callback) {
            var _a;
            const res = this.root.toDict(true, callback);
            return (_a = res.children) !== null && _a !== void 0 ? _a : [];
        }
        /**
         * Update column headers and column width.
         * Return true if at least one column width changed.
         */
        // _updateColumnWidths(options?: UpdateColumnsOptions): boolean {
        _updateColumnWidths() {
            // options = Object.assign({ updateRows: true, renderMarkup: false }, options);
            const defaultMinWidth = 4;
            const vpWidth = this.element.clientWidth;
            // Shorten last column width to avoid h-scrollbar
            // (otherwise resizbing the demo would display a void scrollbar?)
            const FIX_ADJUST_LAST_COL = 1;
            const columns = this.columns;
            const col0 = columns[0];
            let totalWidth = 0;
            let totalWeight = 0;
            let fixedWidth = 0;
            let modified = false;
            // this.element.classList.toggle("wb-grid", isGrid);
            // if (!isGrid && this.isCellNav()) {
            //   this.setCellNav(false);
            // }
            // if (options.calculateCols) {
            if (col0.id !== "*") {
                throw new Error(`First column must have  id '*': got '${col0.id}'.`);
            }
            // Gather width definitions
            this._columnsById = {};
            for (const col of columns) {
                this._columnsById[col.id] = col;
                const cw = col.width;
                if (col.id === "*" && col !== col0) {
                    throw new Error(`Column id '*' must be defined only once: '${col.title}'.`);
                }
                if (!cw || cw === "*") {
                    col._weight = 1.0;
                    totalWeight += 1.0;
                }
                else if (typeof cw === "number") {
                    col._weight = cw;
                    totalWeight += cw;
                }
                else if (typeof cw === "string" && cw.endsWith("px")) {
                    col._weight = 0;
                    const px = parseFloat(cw.slice(0, -2));
                    if (col._widthPx != px) {
                        modified = true;
                        col._widthPx = px;
                    }
                    fixedWidth += px;
                }
                else {
                    error(`Invalid column width: ${cw} (expected string ending with 'px' or number, e.g. "<num>px" or <int>).`);
                }
            }
            // Share remaining space between non-fixed columns
            const restPx = Math.max(0, vpWidth - fixedWidth);
            let ofsPx = 0;
            for (const col of columns) {
                let minWidth;
                if (col._weight) {
                    const cmw = col.minWidth;
                    if (typeof cmw === "number") {
                        minWidth = cmw;
                    }
                    else if (typeof cmw === "string" && cmw.endsWith("px")) {
                        minWidth = parseFloat(cmw.slice(0, -2));
                    }
                    else {
                        minWidth = defaultMinWidth;
                    }
                    const px = Math.max(minWidth, (restPx * col._weight) / totalWeight);
                    if (col._widthPx != px) {
                        modified = true;
                        col._widthPx = px;
                    }
                }
                col._ofsPx = ofsPx;
                ofsPx += col._widthPx;
            }
            columns[columns.length - 1]._widthPx -= FIX_ADJUST_LAST_COL;
            totalWidth = ofsPx - FIX_ADJUST_LAST_COL;
            const tw = `${totalWidth}px`;
            this.headerElement.style.width = tw;
            this.listContainerElement.style.width = tw;
            // }
            // Every column has now a calculated `_ofsPx` and `_widthPx`
            // this.logInfo("UC", this.columns, vpWidth, this.element.clientWidth, this.element);
            // console.trace();
            // util.error("BREAK");
            // if (modified) {
            //   this._renderHeaderMarkup();
            //   if (options.renderMarkup) {
            //     this.update(ChangeType.header, { removeMarkup: true });
            //   } else if (options.updateRows) {
            //     this._updateRows();
            //   }
            // }
            return modified;
        }
        /** Create/update header markup from `this.columns` definition.
         * @internal
         */
        _renderHeaderMarkup() {
            assert(this.headerElement, "Expected a headerElement");
            const wantHeader = this.hasHeader();
            setElemDisplay(this.headerElement, wantHeader);
            if (!wantHeader) {
                return;
            }
            const colCount = this.columns.length;
            const headerRow = this.headerElement.querySelector(".wb-row");
            assert(headerRow, "Expected a row in header element");
            headerRow.innerHTML = "<span class='wb-col'></span>".repeat(colCount);
            for (let i = 0; i < colCount; i++) {
                const col = this.columns[i];
                const colElem = headerRow.children[i];
                colElem.style.left = col._ofsPx + "px";
                colElem.style.width = col._widthPx + "px";
                // Add classes from `columns` definition to `<div.wb-col>` cells
                if (typeof col.headerClasses === "string") {
                    col.headerClasses
                        ? colElem.classList.add(...col.headerClasses.split(" "))
                        : 0;
                }
                else {
                    col.classes ? colElem.classList.add(...col.classes.split(" ")) : 0;
                }
                const title = escapeHtml(col.title || col.id);
                let tooltip = "";
                if (col.tooltip) {
                    tooltip = escapeTooltip(col.tooltip);
                    tooltip = ` title="${tooltip}"`;
                }
                let resizer = "";
                if (i < colCount - 1) {
                    resizer = '<span class="wb-col-resizer"></span>';
                }
                colElem.innerHTML = `<span class="wb-col-title"${tooltip}>${title}</span>${resizer}`;
                if (this.isCellNav()) {
                    colElem.classList.toggle("wb-active", i === this.activeColIdx);
                }
            }
        }
        /**
         * Render pending changes that were scheduled using {@link WunderbaumNode.update} if any.
         *
         * This is hardly ever neccessary, since we normally either
         * - call `update(ChangeType.TYPE)` (async, throttled), or
         * - call `update(ChangeType.TYPE, {immediate: true})` (synchronous)
         *
         * `updatePendingModifications()` will only force immediate execution of
         * pending async changes if any.
         */
        updatePendingModifications() {
            if (this.pendingChangeTypes.size > 0) {
                this._updateViewportImmediately();
            }
        }
        /**
         * This is the actual update method, which is wrapped inside a throttle method.
         * It calls `updateColumns()` and `_updateRows()`.
         *
         * This protected method should not be called directly but via
         * {@link WunderbaumNode.update}`, {@link Wunderbaum.update},
         * or {@link Wunderbaum.updatePendingModifications}.
         * @internal
         */
        _updateViewportImmediately() {
            var _a;
            if (this._disableUpdateCount) {
                this.log(`_updateViewportImmediately() IGNORED (disable level: ${this._disableUpdateCount}).`);
                this._disableUpdateIgnoreCount++;
                return;
            }
            if (this._updateViewportThrottled.pending()) {
                // this.logWarn(`_updateViewportImmediately() cancel pending timer.`);
                this._updateViewportThrottled.cancel();
            }
            // Shorten container height to avoid v-scrollbar
            const FIX_ADJUST_HEIGHT = 1;
            const RF = RenderFlag;
            const pending = new Set(this.pendingChangeTypes);
            this.pendingChangeTypes.clear();
            const scrollOnly = pending.has(RF.scroll) && pending.size === 1;
            if (scrollOnly) {
                this._updateRows({ newNodesOnly: true });
                // this.log("_updateViewportImmediately(): scroll only.");
            }
            else {
                this.log("_updateViewportImmediately():", pending);
                if (this.options.adjustHeight !== false) {
                    let height = this.listContainerElement.clientHeight;
                    const headerHeight = this.headerElement.clientHeight; // May be 0
                    const wantHeight = this.element.clientHeight - headerHeight - FIX_ADJUST_HEIGHT;
                    if (Math.abs(height - wantHeight) > 1.0) {
                        // this.log("resize", height, wantHeight);
                        this.listContainerElement.style.height = wantHeight + "px";
                        height = wantHeight;
                    }
                }
                // console.profile(`_updateViewportImmediately()`)
                if (pending.has(RF.clearMarkup)) {
                    this.visit((n) => {
                        n.removeMarkup();
                    });
                }
                // let widthModified = false;
                if (pending.has(RF.header)) {
                    // widthModified = this._updateColumnWidths();
                    this._updateColumnWidths();
                    this._renderHeaderMarkup();
                }
                this._updateRows();
                // console.profileEnd(`_updateViewportImmediately()`)
            }
            if (this.options.connectTopBreadcrumb) {
                let path = (_a = this.getTopmostVpNode(true)) === null || _a === void 0 ? void 0 : _a.getPath(false, "title", " > ");
                path = path ? path + " >" : "";
                this.options.connectTopBreadcrumb.textContent = path;
            }
            this._callEvent("update");
        }
        // /**
        //  * Assert that TR order matches the natural node order
        //  * @internal
        //  */
        // protected _validateRows(): boolean {
        //   let trs = this.nodeListElement.childNodes;
        //   let i = 0;
        //   let prev = -1;
        //   let ok = true;
        //   trs.forEach((element) => {
        //     const tr = element as HTMLTableRowElement;
        //     const top = Number.parseInt(tr.style.top);
        //     const n = (<any>tr)._wb_node;
        //     // if (i < 4) {
        //     //   console.info(
        //     //     `TR#${i}, rowIdx=${n._rowIdx} , top=${top}px: '${n.title}'`
        //     //   );
        //     // }
        //     if (prev >= 0 && top !== prev + ROW_HEIGHT) {
        //       n.logWarn(
        //         `TR order mismatch at index ${i}: top=${top}px != ${
        //           prev + ROW_HEIGHT
        //         }`
        //       );
        //       // throw new Error("fault");
        //       ok = false;
        //     }
        //     prev = top;
        //     i++;
        //   });
        //   return ok;
        // }
        /*
         * - Traverse all *visible* nodes of the whole tree, i.e. skip collapsed nodes.
         * - Store count of rows to `tree.treeRowCount`.
         * - Renumber `node._rowIdx` for all visible nodes.
         * - Calculate the index range that must be rendered to fill the viewport
         *   (including upper and lower prefetch)
         * -
         */
        _updateRows(options) {
            // const label = this.logTime("_updateRows");
            // this.log("_updateRows", opts)
            options = Object.assign({ newNodesOnly: false }, options);
            const newNodesOnly = !!options.newNodesOnly;
            const row_height = ROW_HEIGHT;
            const vp_height = this.element.clientHeight;
            const prefetch = RENDER_MAX_PREFETCH;
            // const grace_prefetch = RENDER_MAX_PREFETCH - RENDER_MIN_PREFETCH;
            const ofs = this.element.scrollTop;
            let startIdx = Math.max(0, ofs / row_height - prefetch);
            startIdx = Math.floor(startIdx);
            // Make sure start is always even, so the alternating row colors don't
            // change when scrolling:
            if (startIdx % 2) {
                startIdx--;
            }
            let endIdx = Math.max(0, (ofs + vp_height) / row_height + prefetch);
            endIdx = Math.ceil(endIdx);
            // this.debug("render", opts);
            const obsoleteNodes = new Set();
            this.nodeListElement.childNodes.forEach((elem) => {
                const tr = elem;
                obsoleteNodes.add(tr._wb_node);
            });
            let idx = 0;
            let top = 0;
            let modified = false;
            let prevElem = "first";
            this.visitRows(function (node) {
                // node.log("visit")
                const rowDiv = node._rowElem;
                // Renumber all expanded nodes
                if (node._rowIdx !== idx) {
                    node._rowIdx = idx;
                    modified = true;
                }
                if (idx < startIdx || idx > endIdx) {
                    // row is outside viewport bounds
                    if (rowDiv) {
                        prevElem = rowDiv;
                    }
                }
                else if (rowDiv && newNodesOnly) {
                    obsoleteNodes.delete(node);
                    // no need to update existing node markup
                    rowDiv.style.top = idx * ROW_HEIGHT + "px";
                    prevElem = rowDiv;
                }
                else {
                    obsoleteNodes.delete(node);
                    // Create new markup
                    if (rowDiv) {
                        rowDiv.style.top = idx * ROW_HEIGHT + "px";
                    }
                    node._render({ top: top, after: prevElem });
                    // node.log("render", top, prevElem, "=>", node._rowElem);
                    prevElem = node._rowElem;
                }
                idx++;
                top += row_height;
            });
            this.treeRowCount = idx;
            for (const n of obsoleteNodes) {
                n._callEvent("discard");
                n.removeMarkup();
            }
            // Resize tree container
            this.nodeListElement.style.height = `${top}px`;
            // this.log(
            //   `_updateRows(scrollOfs:${ofs}, ${startIdx}..${endIdx})`,
            //   this.nodeListElement.style.height
            // );
            // this.logTimeEnd(label);
            // this._validateRows();
            return modified;
        }
        /**
         * Call `callback(node)` for all nodes in hierarchical order (depth-first, pre-order).
         * @see {@link IterableIterator<WunderbaumNode>}, {@link WunderbaumNode.visit}.
         *
         * @param {function} callback the callback function.
         *     Return false to stop iteration, return "skip" to skip this node and
         *     children only.
         * @returns {boolean} false, if the iterator was stopped.
         */
        visit(callback) {
            return this.root.visit(callback, false);
        }
        /**
         * Call callback(node) for all nodes in vertical order, top down (or bottom up).
         *
         * Note that this considers expansion state, i.e. filtered nodes and children
         * of collapsed nodes are skipped, unless `includeHidden` is set.
         *
         * Stop iteration if callback() returns false.<br>
         * Return false if iteration was stopped.
         *
         * @returns {boolean} false if iteration was canceled
         */
        visitRows(callback, options) {
            if (!this.root.hasChildren()) {
                return false;
            }
            if (options && options.reverse) {
                delete options.reverse;
                return this._visitRowsUp(callback, options);
            }
            options = options || {};
            let i, nextIdx, parent, res, siblings, stopNode, siblingOfs = 0, skipFirstNode = options.includeSelf === false, node = options.start || this.root.children[0];
            const includeHidden = !!options.includeHidden;
            const checkFilter = !includeHidden && this.filterMode === "hide";
            parent = node.parent;
            while (parent) {
                // visit siblings
                siblings = parent.children;
                nextIdx = siblings.indexOf(node) + siblingOfs;
                assert(nextIdx >= 0, `Could not find ${node} in parent's children: ${parent}`);
                for (i = nextIdx; i < siblings.length; i++) {
                    node = siblings[i];
                    if (node === stopNode) {
                        return false;
                    }
                    if (checkFilter &&
                        !node.statusNodeType &&
                        !node.match &&
                        !node.subMatchCount) {
                        continue;
                    }
                    if (!skipFirstNode && callback(node) === false) {
                        return false;
                    }
                    skipFirstNode = false;
                    // Dive into node's child nodes
                    if (node.children &&
                        node.children.length &&
                        (includeHidden || node.expanded)) {
                        res = node.visit((n) => {
                            if (n === stopNode) {
                                return false;
                            }
                            if (checkFilter && !n.match && !n.subMatchCount) {
                                return "skip";
                            }
                            if (callback(n) === false) {
                                return false;
                            }
                            if (!includeHidden && n.children && !n.expanded) {
                                return "skip";
                            }
                        }, false);
                        if (res === false) {
                            return false;
                        }
                    }
                }
                // Visit parent nodes (bottom up)
                node = parent;
                parent = parent.parent;
                siblingOfs = 1; //
                if (!parent && options.wrap) {
                    this.logDebug("visitRows(): wrap around");
                    assert(options.start, "`wrap` option requires `start`");
                    stopNode = options.start;
                    options.wrap = false;
                    parent = this.root;
                    siblingOfs = 0;
                }
            }
            return true;
        }
        /**
         * Call fn(node) for all nodes in vertical order, bottom up.
         * @internal
         */
        _visitRowsUp(callback, options) {
            let children, idx, parent, node = options.start || this.root.children[0];
            const includeHidden = !!options.includeHidden;
            if (options.includeSelf !== false) {
                if (callback(node) === false) {
                    return false;
                }
            }
            while (true) {
                parent = node.parent;
                children = parent.children;
                if (children[0] === node) {
                    // If this is already the first sibling, goto parent
                    node = parent;
                    if (!node.parent) {
                        break; // first node of the tree
                    }
                    children = parent.children;
                }
                else {
                    // Otherwise, goto prev. sibling
                    idx = children.indexOf(node);
                    node = children[idx - 1];
                    // If the prev. sibling has children, follow down to last descendant
                    while ((includeHidden || node.expanded) &&
                        node.children &&
                        node.children.length) {
                        children = node.children;
                        parent = node;
                        node = children[children.length - 1];
                    }
                }
                // Skip invisible
                if (!includeHidden && !node.isVisible()) {
                    continue;
                }
                if (callback(node) === false) {
                    return false;
                }
            }
            return true;
        }
        /**
         * Reload the tree with a new source.
         *
         * Previous data is cleared. Note that also column- and type defintions may
         * be passed with the `source` object.
         */
        load(source) {
            this.clear();
            return this.root.load(source);
        }
        /**
         * Disable render requests during operations that would trigger many updates.
         *
         * ```js
         * try {
         *   tree.enableUpdate(false);
         *   // ... (long running operation that would trigger many updates)
         *   foo();
         *   // ... NOTE: make sure that async operations have finished, e.g.
         *   await foo();
         * } finally {
         *   tree.enableUpdate(true);
         * }
         * ```
         */
        enableUpdate(flag) {
            /*
                5  7  9                20       25   30
            1   >-------------------------------------<
            2      >--------------------<
            3         >--------------------------<
            */
            if (flag) {
                assert(this._disableUpdateCount > 0, "enableUpdate(true) was called too often");
                this._disableUpdateCount--;
                // this.logDebug(
                //   `enableUpdate(${flag}): count -> ${this._disableUpdateCount}...`
                // );
                if (this._disableUpdateCount === 0) {
                    this.logDebug(`enableUpdate(): active again. Re-painting to catch up with ${this._disableUpdateIgnoreCount} ignored update requests...`);
                    this._disableUpdateIgnoreCount = 0;
                    this.update(ChangeType.any, { immediate: true });
                }
            }
            else {
                this._disableUpdateCount++;
                // this.logDebug(
                //   `enableUpdate(${flag}): count -> ${this._disableUpdateCount}...`
                // );
                // this._disableUpdate = Date.now();
            }
            // return !flag; // return previous value
        }
        /* ---------------------------------------------------------------------------
         * FILTER
         * -------------------------------------------------------------------------*/
        /**
         * Dim or hide nodes.
         */
        filterNodes(filter, options) {
            return this.extensions.filter.filterNodes(filter, options);
        }
        /**
         * Dim or hide whole branches.
         */
        filterBranches(filter, options) {
            return this.extensions.filter.filterBranches(filter, options);
        }
        /**
         * Reset the filter.
         */
        clearFilter() {
            return this.extensions.filter.clearFilter();
        }
        /**
         * Return true if a filter is currently applied.
         */
        isFilterActive() {
            return !!this.filterMode;
        }
        /**
         * Re-apply current filter.
         */
        updateFilter() {
            return this.extensions.filter.updateFilter();
        }
    }
    Wunderbaum.sequence = 0;
    /** Wunderbaum release version number "MAJOR.MINOR.PATCH". */
    Wunderbaum.version = "v0.8.2"; // Set to semver by 'grunt release'
    /** Expose some useful methods of the util.ts module as `Wunderbaum.util`. */
    Wunderbaum.util = util;

    exports.Wunderbaum = Wunderbaum;

}));
