function login() {
    var data = {
        username: $("input[name=username]").val(),
        password: $("input[name=password]").val(),
    };
    var register = $("input[name=register]").attr("checked");
    $("#errormsg").html('')
    $.ajax({
        type: register ? "POST" : "GET",
        url: register ? "/api/create_account" : "/api/login",
        data: data,
        success: function(r) {
            if (r.status == "ok") {
                document.cookie =
                    'auth='+r.auth+
                    '; expires=Thu, 1 Aug 2030 20:00:00 UTC; path=/';
                window.location.href = "/";
            } else {
                $("#errormsg").html(r.error)
            }
        }
    });
    return false;
}

function submit() {
try {
    if (typeof(apisecret) == 'undefined') return false; // Not logged in
    var data = {
        news_id: $("input[name=news_id]").val(),
        title: $("input[name=title]").val(),
        url: $("input[name=url]").val(),
        text: $("textarea[name=text]").val(),
        apisecret: apisecret
    };
    var del = $("input[name=del]").length && $("input[name=del]").attr("checked");
    $.ajax({
        type: "POST",
        url: del ? "/api/delnews" : "/api/submit",
        data: data,
        success: function(r) {
            if (r.status == "ok") {
                if (r.news_id == -1) {
                    window.location.href = "/";
                } else {
                  if (r.duplicated == 1) {
                    window.location.href = "/news/"+r.news_id+"?duplicated=1";
                  } else {
                    window.location.href = "/news/"+r.news_id;
                  }
                }
            } else {
                $("#errormsg").html(r.error)
            }
        }
    });
} catch (e) {
}
    return false;
}

function update_profile() {
    var data = {
        email: $("input[name=email]").val(),
        password: $("input[name=password]").val(),
        about: $("textarea[name=about]").val(),
        apisecret: apisecret
    };
    $.ajax({
        type: "POST",
        url: "/api/updateprofile",
        data: data,
        success: function(r) {
            if (r.status == "ok") {
                window.location.reload();
            } else {
                $("#errormsg").html(r.error)
            }
        }
    });
    return false;
}

function post_comment() {
    var data = {
        news_id: $("input[name=news_id]").val(),
        comment_id: $("input[name=comment_id]").val(),
        parent_id: $("input[name=parent_id]").val(),
        comment: $("textarea[name=comment]").val(),
        apisecret: apisecret
    };
    $.ajax({
        type: "POST",
        url: "/api/postcomment",
        data: data,
        success: function(r) {
            if (r.status == "ok") {
                if (r.op == "insert") {
                    window.location.href = "/news/"+r.news_id+"?r="+Math.random()+"#"+r.news_id+"-"+r.comment_id;
                } else if (r.op == "update") {
                    window.location.href = "/editcomment/"+r.news_id+"/"+r.comment_id;
                } else if (r.op == "delete") {
                    window.location.href = "/news/"+r.news_id;
                }
            } else {
                $("#errormsg").html(r.error)
            }
        }
    });
    return false;
}

function setKeyboardNavigation() {
    $(function() {
        $(document).keyup(function(e) {
            var active = $('article.active');
            if (e.which == 74 || e.which == 75) {
                var newActive;
                if (active.length == 0) {
                    if (e.which == 74) {
                        newActive = $('article').first();
                    } else {
                        newActive = $('article').last();
                    }
                } else if (e.which == 74){
                    newActive = $($('article').get($('article').index(active)+1));
                } else if (e.which == 75){
                    var index = $('article').index(active);
                    if (index == 0) return;
                    newActive = $($('article').get(index-1));
                }
                if (newActive.length == 0) return;
                active.removeClass('active');
                newActive.addClass('active');
                if ($(window).scrollTop() > newActive.offset().top)
                    $('html, body').animate({ scrollTop: newActive.offset().top - 10 }, 100);
                if ($(window).scrollTop() + $(window).height() < newActive.offset().top)
                    $('html, body').animate({ scrollTop: newActive.offset().top - $(window).height() + newActive.height() + 10 }, 100);
            }
            if (e.which == 13 && active.length > 0) {
                location.href = active.find('h2 a').attr('href');
            }
            if (e.which == 65 && active.length > 0) {
                active.find('.uparrow').click();
            }
            if (e.which == 90 && active.length > 0) {
                active.find('.downarrow').click();
            }
        });
        $('#newslist article').each(function(i,news) {
            $(news).click(function() {
                var active = $('article.active');
                active.removeClass('active');
                $(news).addClass('active');
            });
        });
    });
}

// Install the onclick event in all news arrows the user did not voted already.
$(function() {
    $('#newslist article').each(function(i,news) {
        var news_id = $(news).data("newsId");
        news = $(news);
        up = news.find(".uparrow");
        down = news.find(".downarrow");
        var voted = up.hasClass("voted") || down.hasClass("voted");
        if (!voted) {
            up.click(function(e) {
                if (typeof(apisecret) == 'undefined') return; // Not logged in
                e.preventDefault();
                var data = {
                    news_id: news_id,
                    vote_type: "up",
                    apisecret: apisecret
                };
                $.ajax({
                    type: "POST",
                    url: "/api/votenews",
                    data: data,
                    success: function(r) {
                        if (r.status == "ok") {
                            n = $("article[data-news-id="+news_id+"]");
                            n.find(".uparrow").addClass("voted");
                            n.find(".downarrow").addClass("disabled");
                        } else {
                            alert(r.error);
                        }
                    }
                });
            });

            down.click(function(e) {
                if (typeof(apisecret) == 'undefined') return; // Not logged in
                e.preventDefault();
                var data = {
                    news_id : news_id,
                    vote_type: "down",
                    apisecret: apisecret
                };
                $.ajax({
                    type: "POST",
                    url: "/api/votenews",
                    data: data,
                    success: function(r) {
                        if (r.status == "ok") {
                            n = $("article[data-news-id="+news_id+"]");
                            n.find(".uparrow").addClass("disabled");
                            n.find(".downarrow").addClass("voted");
                        } else {
                            alert(r.error);
                        }
                    }
                });
            });
        }
    });
});

// Install the onclick event in all comments arrows the user did not
// voted already.
$(function() {
    $('#comments article.comment').each(function(i,comment) {
        var comment_id = $(comment).data("commentId");
        comment = $(comment);
        up = comment.find(".uparrow");
        down = comment.find(".downarrow");
        var voted = up.hasClass("voted") || down.hasClass("voted");
        if (!voted) {
            up.click(function(e) {
                if (typeof(apisecret) == 'undefined') return; // Not logged in
                e.preventDefault();
                var data = {
                    comment_id: comment_id,
                    vote_type: "up",
                    apisecret: apisecret
                };
                $.ajax({
                    type: "POST",
                    url: "/api/votecomment",
                    data: data,
                    success: function(r) {
                        if (r.status == "ok") {
                            $('article[data-comment-id="'+r.comment_id+'"]').find(".uparrow").addClass("voted")
                            $('article[data-comment-id="'+r.comment_id+'"]').find(".downarrow").addClass("disabled")
                        } else {
                            alert(r.error);
                        }
                    }
                });
            });
            down.click(function(e) {
                if (typeof(apisecret) == 'undefined') return; // Not logged in
                e.preventDefault();
                var data = {
                    comment_id: comment_id,
                    vote_type: "down",
                    apisecret: apisecret
                };
                $.ajax({
                    type: "POST",
                    url: "/api/votecomment",
                    data: data,
                    success: function(r) {
                        if (r.status == "ok") {
                            $('article[data-comment-id="'+r.comment_id+'"]').find(".uparrow").addClass("disabled")
                            $('article[data-comment-id="'+r.comment_id+'"]').find(".downarrow").addClass("voted")
                        } else {
                            alert(r.error);
                        }
                    }
                });
            });
        }
    });
});






NIP.initfuncs = {
  loginform: function() {
    $('#loginform').submit(login);
    $('#username').focus();
  },
  submitnews: function() {
    $('#submitnews').submit(submit);
    $('#title').focus();
  },
  postcomment: function() {
    $('#commentform').submit(post_comment);
  },
  updateprofile: function() {
    $('#profileform').submit(update_profile);
  }

}

NIP.startup = function() {
  $.each(NIP.init, function(i,e) {
    NIP.initfuncs[e].call();
  });
}


$(function() {
  NIP.startup();

  $('#newslist').click(function(e) {
    var $e = $(e.target);
    if ($e.hasClass('news-link')) {
      _gaq.push(['_trackEvent', 'News', 'link', $e.text()]);
    }
  });
  //setKeyboardNavigation();
});

