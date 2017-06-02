/*-
 * Copyright (C) 2017, Vi Grey
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

$(document).ready(function() {
  $('#reg').click(function() {
    loader();
    $('.loader .success').hide();
    $('.loader .failure').hide();
    $('#register .description').text('Enter a nickname for your U2F security key.')
    $('#filter').fadeIn(100);
  });
  $('#filter:not(.on)').click(function(e) {
    if (e.target === this) {
      $('.loader').removeClass('finished')
      $('#filter').removeClass('finished');
      $('#filter').fadeOut(100);
    }
  });
  $('.close').click(function() {
    $('.loader').removeClass('finished')
    $('#filter').removeClass('finished');
    $('#filter').fadeOut(100);
  });
  if ($('#sign').length) {
    sign();
    $('#sign .description').text('Press the button on your U2F security key to log in.')
    $('#filter').fadeIn(100);
  }
});
function loader() {
  $('.loader').css({
    animation: '',
    '-webkit-animation': ''
  });
  register()
  $('#register .description').text('Press the button on your U2F security key to register it.')
  $('.loader').circleProgress()
  $('.loader').circleProgress('redraw')
  $('.loader').circleProgress({
    animation: {
      duration: 400,
      easing: 'circleProgressEasing'
    },
    value: 0.25,
    size: 56,
    thickness: 8,
    emptyFill: '#d2d2d2',
    fill: '#0066c8',
    animationStartValue: .25
  });
}
function loaderSuccess() {
  $('.failure').hide();
  $('.loader').circleProgress({
    value: 1,
    fill:'#0cc800'
  }).on('circle-animation-end', function() {
    $(this).off('circle-animation-end');
    if ($(this).hasClass('finished')) {
      $(this).circleProgress({
        animation: false
      });
      $(this).css({
        animation: 'none',
        '-webkit-animation': 'none'
      });
      $(this).children('.success').show();
      $('#register .description').text('Successfully registered your U2F security key!');
      $('#filter').addClass('finished')
      setTimeout(function() {
        if ($('#filter').hasClass('finished')) {
          $('#filter').fadeOut(100);
        }
        $('.loader').removeClass('finished');
      }, 2000);
    }
  });
}
function loaderFailure(errorCode) {
  $('.success').hide();
  $('.loader').circleProgress({
    value: 1,
    fill:'#ea2d2d'
  }).on('circle-animation-end', function() {
    $(this).off('circle-animation-end');
    if ($(this).hasClass('finished')) {
      $(this).circleProgress({
        animation: false
      });
      $(this).css({
        animation: 'none',
        '-webkit-animation': 'none'
      });
      $(this).children('.failure').show();
      if (errorCode == 255) {
        $('#register .description').text('Problem connecting to server.');
      } else if (errorCode == 4) {
        $('#register .description').text('U2F security key already registered.');
      } else if (errorCode == 5) {
        $('#register .description').text('Timed out waiting for U2F security key action.');
      } else {
        $('#register .description').text('Failed to register your U2F security key.');
      }
      $('#filter').addClass('finished')
    }
  });
}
function checkError(resp) {
  if (!('errorCode' in resp)) {
    return false;
  }
  if (resp.errorCode === 0) {
    return false;
  }
  $('.loader').addClass('finished');
  loaderFailure(resp.errorCode);
  return true;
}
function u2fRegistered(resp) {
  if (checkError(resp)) {
    return;
  }
  $.post('/registerResponse', JSON.stringify(resp), function() {
    $('.loader').addClass('finished');
    loaderSuccess();
  }).fail(function() {
    $('.loader').addClass('finished');
    loaderFailure(resp.errorCode);
  });
}
function register() {
  $.getJSON('/registerRequest', function(req) {
    u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
  }).fail(function() {
    $('.loader').addClass('finished');
    loaderFailure(255);
  });
}
function u2fSigned(resp) {
  if (checkError(resp)) {
    window.open("/","_self");
    return
  }
  $.post('/login', {'signature': JSON.stringify(resp)}, function(data) {
    window.open("/profile","_self");
  }).fail(function() {
    window.open("/","_self");
  });
}
function sign() {
  console.log(0);
  var req = $.parseJSON($('#challenge').html());
  console.log(1);
  console.log(req.appId);
  u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
}
