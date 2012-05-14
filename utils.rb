# encoding: UTF-8
#
# Check that the list of parameters specified exist.
# If at least one is missing false is returned, otherwise true is returned.
#
# If a parameter is specified as as symbol only existence is tested.
# If it is specified as a string the parameter must also meet the condition
# of being a non empty string.
def check_params *required
    required.each{|p|
        params[p].strip! if params[p] and params[p].is_a? String
        if !params[p] or (p.is_a? String and params[p].length == 0)
            return false
        end
    }
    true
end

def check_api_secret
    return false if !$user
    params["apisecret"] and (params["apisecret"] == $user["apisecret"])
end

################################################################################
# User and authentication
################################################################################

# Try to authenticate the user, if the credentials are ok we populate the
# $user global with the user information.
# Otherwise $user is set to nil, so you can test for authenticated user
# just with: if $user ...
#
# Return value: none, the function works by side effect.
def auth_user(auth)
    return if !auth
    id = $r.get("auth:#{auth}")
    return if !id
    user = $r.hgetall("user:#{id}")
    $user = user if user.length > 0
end

# In Lamer News users get karma visiting the site.
# Increment the user karma by KarmaIncrementAmount if the latest increment
# was performed more than KarmaIncrementInterval seconds ago.
#
# Return value: none.
#
# Notes: this function must be called only in the context of a logged in
#        user.
#
# Side effects: the user karma is incremented and the $user hash updated.
def increment_karma_if_needed
    if $user['karma_incr_time'].to_i < (Time.now.to_i-KarmaIncrementInterval)
        userkey = "user:#{$user['id']}"
        $r.hset(userkey,"karma_incr_time",Time.now.to_i)
        increment_user_karma_by($user['id'],KarmaIncrementAmount)
    end
end

# Increment the user karma by the specified amount and make sure to
# update $user to reflect the change if it is the same user id.
def increment_user_karma_by(user_id,increment)
    userkey = "user:#{user_id}"
    $r.hincrby(userkey,"karma",increment)
    if $user and ($user['id'].to_i == user_id.to_i)
        $user['karma'] = $user['karma'].to_i + increment
    end
end

# Return the specified user karma.
def get_user_karma(user_id)
    return $user['karma'].to_i if $user and (user_id.to_i == $user['id'].to_i)
    userkey = "user:#{user_id}"
    karma = $r.hget(userkey,"karma")
    karma ? karma.to_i : 0
end

# Return the hex representation of an unguessable 160 bit random number.
def get_rand
    rand = "";
    File.open("/dev/urandom").read(20).each_byte{|x| rand << sprintf("%02x",x)}
    rand
end

# Create a new user with the specified username/password
#
# Return value: the function returns two values, the first is the
#               auth token if the registration succeeded, otherwise
#               is nil. The second is the error message if the function
#               failed (detected testing the first return value).
def create_user(username,password)
    if $r.exists("username.to.id:#{username.downcase}")
        return nil, "El nombre de usuario está siendo usado, pruebe uno diferente."
    end
    if rate_limit_by_ip(3600*15,"create_user",request.ip)
        return nil, "Por favor espere algún tiempo antes de crear otro usuario."
    end
    id = $r.incr("users.count")
    auth_token = get_rand
    salt = get_rand
    $r.hmset("user:#{id}",
        "id",id,
        "username",username,
        "salt",salt,
        "password",hash_password(password,salt),
        "ctime",Time.now.to_i,
        "karma",UserInitialKarma,
        "about","",
        "email","",
        "auth",auth_token,
        "apisecret",get_rand,
        "flags","",
        "karma_incr_time",Time.new.to_i)
    $r.set("username.to.id:#{username.downcase}",id)
    $r.set("auth:#{auth_token}",id)
    return auth_token,nil
end

# Update the specified user authentication token with a random generated
# one. This in other words means to logout all the sessions open for that
# user.
#
# Return value: on success the new token is returned. Otherwise nil.
# Side effect: the auth token is modified.
def update_auth_token(user_id)
    user = get_user_by_id(user_id)
    return nil if !user
    $r.del("auth:#{user['auth']}")
    new_auth_token = get_rand
    $r.hmset("user:#{user_id}","auth",new_auth_token)
    $r.set("auth:#{new_auth_token}",user_id)
    return new_auth_token
end

# Turn the password into an hashed one, using PBKDF2 with HMAC-SHA1
# and 160 bit output.
def hash_password(password,salt)
    p = PBKDF2.new do |p|
        p.iterations = PBKDF2Iterations
        p.password = password
        p.salt = salt
        p.key_length = 160/8
    end
    p.hex_string
end

# Return the user from the ID.
def get_user_by_id(id)
    $r.hgetall("user:#{id}")
end

# Return the user from the username.
def get_user_by_username(username)
    id = $r.get("username.to.id:#{username.downcase}")
    return nil if !id
    get_user_by_id(id)
end

# Check if the username/password pair identifies an user.
# If so the auth token and form secret are returned, otherwise nil is returned.
def check_user_credentials(username,password)
    user = get_user_by_username(username)
    return nil if !user
    hp = hash_password(password,user['salt'])
    (user['password'] == hp) ? [user['auth'],user['apisecret']] : nil
end

# Has the user submitted a news story in the last `NewsSubmissionBreak` seconds?
def submitted_recently
  #TODO: remove
  return false
  #allowed_to_post_in_seconds > 0
end

# Check if the URL is already posted
def is_duplicated?(url)
  $r.sismember('news:url', OpenSSL::Digest::SHA1.new(url).to_s)
end


# Indicates when the user is allowed to submit another story after the last.
def allowed_to_post_in_seconds
    $r.ttl("user:#{$user['id']}:submitted_recently")
end

# Add the specified set of flags to the user.
# Returns false on error (non existing user), otherwise true is returned.
#
# Current flags:
# 'a'   Administrator.
# 'k'   Karma source, can transfer more karma than owned.
# 'n'   Open links to new windows.
#
def user_add_flags(user_id,flags)
    user = get_user_by_id(user_id)
    return false if !user
    newflags = user['flags']
    flags.each_char{|flag|
        newflags << flag if not user_has_flags?(user,flag)
    }
    # Note: race condition here if somebody touched the same field
    # at the same time: very unlkely and not critical so not using WATCH
    $r.hset("user:#{user['id']}","flags",newflags)
    true
end

# Check if the user has all the specified flags at the same time.
# Returns true or false.
def user_has_flags?(user,flags)
    flags.each_char {|flag|
        return false if not user['flags'].index(flag)
    }
    true
end

def user_is_admin?(user)
    user_has_flags?(user,"a")
end

################################################################################
# News
################################################################################

# Fetch one or more (if an Array is passed) news from Redis by id.
# Note that we also load other informations about the news like
# the username of the poster and other informations needed to render
# the news into HTML.
#
# Doing this in a centralized way offers us the ability to exploit
# Redis pipelining.
def get_news_by_id(news_ids,opt={})
    result = []
    if !news_ids.is_a? Array
        opt[:single] = true
        news_ids = [news_ids]
    end
    news = $r.pipelined {
        news_ids.each{|nid|
            $r.hgetall("news:#{nid}")
        }
    }
    return [] if !news # Can happen only if news_ids is an empty array.

    # Remove empty elements
    news = news.select{|x| x.length > 0}
    if news.length == 0
        return opt[:single] ? nil : []
    end

    # Get all the news
    $r.pipelined {
        news.each{|n|
            # Adjust rank if too different from the real-time value.
            hash = {}
            n.each_slice(2) {|k,v|
                hash[k] = v
            }
            update_news_rank_if_needed(hash) if opt[:update_rank]
            result << hash
        }
    }

    # Get the associated users information
    usernames = $r.pipelined {
        result.each{|n|
            $r.hget("user:#{n["user_id"]}","username")
        }
    }
    result.each_with_index{|n,i|
        n["username"] = usernames[i]
    }

    # Load $User vote information if we are in the context of a
    # registered user.
    if $user
        votes = $r.pipelined {
            result.each{|n|
                $r.zscore("news.up:#{n["id"]}",$user["id"])
                $r.zscore("news.down:#{n["id"]}",$user["id"])
            }
        }
        result.each_with_index{|n,i|
            if votes[i*2]
                n["voted"] = :up
            elsif votes[(i*2)+1]
                n["voted"] = :down
            end
        }
    end

    # Return an array if we got an array as input, otherwise
    # the single element the caller requested.
    opt[:single] ? result[0] : result
end

# Vote the specified news in the context of a given user.
# type is either :up or :down
#
# The function takes care of the following:
# 1) The vote is not duplicated.
# 2) That the karma is decreased from voting user, accordingly to vote type.
# 3) That the karma is transfered to the author of the post, if different.
# 4) That the news score is updaed.
#
# Return value: two return values are returned: rank,error
#
# If the fucntion is successful rank is not nil, and represents the news karma
# after the vote was registered. The error is set to nil.
#
# On error the returned karma is false, and error is a string describing the
# error that prevented the vote.
def vote_news(news_id,user_id,vote_type)
    # Fetch news and user
    user = ($user and $user["id"] == user_id) ? $user : get_user_by_id(user_id)
    news = get_news_by_id(news_id)
    return false,"No such news or user." if !news or !user

    # Now it's time to check if the user already voted that news, either
    # up or down. If so return now.
    if $r.zscore("news.up:#{news_id}",user_id) or
       $r.zscore("news.down:#{news_id}",user_id)
       return false,"Voto duplicado."
    end

    # Check if the user has enough karma to perform this operation
    if $user['id'] != news['user_id']
        if (vote_type == :up and
             (get_user_karma(user_id) < NewsUpvoteMinKarma)) or
           (vote_type == :down and
             (get_user_karma(user_id) < NewsDownvoteMinKarma))
            return false,"No tienes suficiente karma para votar #{vote_type}"
        end
    end

    # News was not already voted by that user. Add the vote.
    # Note that even if there is a race condition here and the user may be
    # voting from another device/API in the time between the ZSCORE check
    # and the zadd, this will not result in inconsistencies as we will just
    # update the vote time with ZADD.
    if $r.zadd("news.#{vote_type}:#{news_id}", Time.now.to_i, user_id)
        $r.hincrby("news:#{news_id}",vote_type,1)
    end
    $r.zadd("user.saved:#{user_id}", Time.now.to_i, news_id) if vote_type == :up

    # Compute the new values of score and karma, updating the news accordingly.
    score = compute_news_score(news)
    news["score"] = score
    rank = compute_news_rank(news)
    $r.hmset("news:#{news_id}",
        "score",score,
        "rank",rank)
    $r.zadd("news.top",rank,news_id)

    # Remove some karma to the user if needed, and transfer karma to the
    # news owner in the case of an upvote.
    if $user['id'] != news['user_id']
        if vote_type == :up
            increment_user_karma_by(user_id,-NewsUpvoteKarmaCost)
            increment_user_karma_by(news['user_id'],NewsUpvoteKarmaTransfered)
        else
            increment_user_karma_by(user_id,-NewsDownvoteKarmaCost)
        end
    end

    return rank,nil
end

# Given the news compute its score.
# No side effects.
def compute_news_score(news)
    upvotes = $r.zrange("news.up:#{news["id"]}",0,-1,:withscores => true)
    downvotes = $r.zrange("news.down:#{news["id"]}",0,-1,:withscores => true)
    # FIXME: For now we are doing a naive sum of votes, without time-based
    # filtering, nor IP filtering.
    # We could use just ZCARD here of course, but I'm using ZRANGE already
    # since this is what is needed in the long term for vote analysis.
    score = (upvotes.length/2) - (downvotes.length/2)
    # Now let's add the logarithm of the sum of all the votes, since
    # something with 5 up and 5 down is less interesting than something
    # with 50 up and 50 donw.
    votes = upvotes.length/2+downvotes.length/2
    if votes > NewsScoreLogStart
        score += Math.log(votes-NewsScoreLogStart)*NewsScoreLogBooster
    end
    score
end

# Given the news compute its rank, that is function of time and score.
#
# The general forumla is RANK = SCORE / (AGE ^ AGING_FACTOR)
def compute_news_rank(news)
    age = (Time.now.to_i - news["ctime"].to_i)+NewsAgePadding
    return (news["score"].to_f)/((age/3600)**RankAgingFactor)
end

# Add a news with the specified url or text.
#
# If an url is passed but was already posted in the latest 48 hours the
# news is not inserted, and the ID of the old news with the same URL is
# returned.
#
# Return value: the ID of the inserted news, or the ID of the news with
# the same URL recently added.
def insert_news(title,url,text,user_id)
    # If we don't have an url but a comment, we turn the url into
    # text://....first comment..., so it is just a special case of
    # title+url anyway.
    textpost = url.length == 0
    if url.length == 0
        url = "text://"+text[0...CommentMaxLength]
    end
    # We can finally insert the news.
    ctime = Time.new.to_i
    news_id = $r.incr("news.count")
    $r.hmset("news:#{news_id}",
        "id", news_id,
        "title", title,
        "url", url,
        "user_id", user_id,
        "ctime", ctime,
        "score", 0,
        "rank", 0,
        "up", 0,
        "down", 0,
        "favicon", 0,
        "comments", 0)
    # The posting user virtually upvoted the news posting it
    rank,error = vote_news(news_id,user_id,:up)
    # Add the news to the user submitted news
    $r.zadd("user.posted:#{user_id}",ctime,news_id)
    # Add the news into the chronological view
    $r.zadd("news.cron",ctime,news_id)
    # Add the news into the top view
    $r.zadd("news.top",rank,news_id)
    # Add the news url for some time to avoid reposts in short time
    $r.setex("url:"+url,PreventRepostTime,news_id) if !textpost
    # Add url's hash to check for duplicates
    $r.sadd('news:url', OpenSSL::Digest::SHA1.new(url).to_s)
    # Set a timeout indicating when the user may post again
    $r.setex("user:#{$user['id']}:submitted_recently",NewsSubmissionBreak,'1')
    return news_id
end

# Edit an already existing news.
#
# On success the news_id is returned.
# On success but when a news deletion is performed (empty title) -1 is returned.
# On failure (for instance news_id does not exist or does not match
#             the specified user_id) false is returned.
def edit_news(news_id,title,url,text,user_id)
    news = get_news_by_id(news_id)
    return false if !news or news['user_id'].to_i != user_id.to_i
    return false if !(news['ctime'].to_i > (Time.now.to_i - NewsEditTime))

    # If we don't have an url but a comment, we turn the url into
    # text://....first comment..., so it is just a special case of
    # title+url anyway.
    textpost = url.length == 0
    if url.length == 0
        url = "text://"+text[0...CommentMaxLength]
    end
    # Even for edits don't allow to change the URL to the one of a
    # recently posted news.
    if !textpost and url != news['url']
        return false if $r.get("url:"+url)
        # No problems with this new url, but the url changed
        # so we unblock the old one and set the block in the new one.
        # Otherwise it is easy to mount a DOS attack.
        $r.del("url:"+news['url'])
        $r.setex("url:"+url,PreventRepostTime,news_id) if !textpost
    end
    # Edit the news fields.
    $r.hmset("news:#{news_id}",
        "title", title,
        "url", url)
    return news_id
end

# Mark an existing news as removed.
def del_news(news_id,user_id)
    news = get_news_by_id(news_id)
    return false if !news or news['user_id'].to_i != user_id.to_i
    return false if !(news['ctime'].to_i > (Time.now.to_i - NewsEditTime))

    $r.hmset("news:#{news_id}","del",1)
    $r.zrem("news.top",news_id)
    $r.zrem("news.cron",news_id)
    return true
end

# Return the host part of the news URL field.
# If the url is in the form text:// nil is returned.
def news_domain(news)
    su = news["url"].split("/")
    domain = (su[0] == "text:") ? nil : su[2]
end

# Assuming the news has an url in the form text:// returns the text
# inside. Otherwise nil is returned.
def news_text(news)
    su = news["url"].split("/")
    (su[0] == "text:") ? news["url"][7..-1] : nil
end

# Updating the rank would require some cron job and worker in theory as
# it is time dependent and we don't want to do any sorting operation at
# page view time. But instead what we do is to compute the rank from the
# score and update it in the sorted set only if there is some sensible error.
# This way ranks are updated incrementally and "live" at every page view
# only for the news where this makes sense, that is, top news.
#
# Note: this function can be called in the context of redis.pipelined {...}
def update_news_rank_if_needed(n)
    real_rank = compute_news_rank(n)
    if (real_rank-n["rank"].to_f).abs > 0.001
        $r.hmset("news:#{n["id"]}","rank",real_rank)
        $r.zadd("news.top",real_rank,n["id"])
        n["rank"] = real_rank.to_s
    end
end

# Generate the main page of the web site, the one where news are ordered by
# rank.
#
# As a side effect thsi function take care of checking if the rank stored
# in the DB is no longer correct (as time is passing) and updates it if
# needed.
#
# This way we can completely avoid having a cron job adjusting our news
# score since this is done incrementally when there are pageviews on the
# site.
def get_top_news(start=0,count=TopNewsPerPage)
    numitems = $r.zcard("news.top")
    news_ids = $r.zrevrange("news.top",start,start+(count-1))
    result = get_news_by_id(news_ids,:update_rank => true)
    # Sort by rank before returning, since we adjusted ranks during iteration.
    return result.sort{|a,b| b["rank"].to_f <=> a["rank"].to_f},numitems
end

# Get news in chronological order.
def get_latest_news(start=0,count=LatestNewsPerPage)
    numitems = $r.zcard("news.cron")
    news_ids = $r.zrevrange("news.cron",start,start+(count-1))
    return get_news_by_id(news_ids,:update_rank => true),numitems
end

# Get saved news of current user
def get_saved_news(user_id,start,count)
    numitems = $r.zcard("user.saved:#{user_id}").to_i
    news_ids = $r.zrevrange("user.saved:#{user_id}",start,start+(count-1))
    return get_news_by_id(news_ids),numitems
end

# Get news posted by a user
def get_user_news(user_id)
  numitems = $r.zcard("user.posted:#{user_id}").to_i
  news_ids = $r.zrevrange("user.posted:#{user_id}",0,NewsPerPage)
  return get_news_by_id(news_ids),numitems
end

###############################################################################
# Views Helper functions
###############################################################################

helpers do

  def get_arrow_class(voted, kind)
    if voted == :up
      kind == :up ? 'voted' : 'disabled'
    elsif voted == :down
      kind == :up ? 'disabled' : 'voted'
    end
  end

  def comment_arrow_class(c, kind)
    down = c['down']
    up = c['up']
    if kind == :up
      if is_logged_in? and up and up.index($user['id'].to_i)
        return "voted"
      elsif is_logged_in? and down and down.index($user['id'].to_i)
        return "disabled"
      end
    else
      if is_logged_in? and up and up.index($user['id'].to_i)
        return "disabled"
      elsif is_logged_in? and down and down.index($user['id'].to_i)
        return "voted"
      end
    end

  end

  def comment_indent(c)
    "margin-left:#{c['level'].to_i*CommentReplyShift}px"
  end

  def gravatar_url(user)
    digest = Digest::MD5.hexdigest(user["email"] || "")
    "http://gravatar.com/avatar/#{digest}?s=48&d=mm"
  end

  def show_edit_link(comment)
    show_edit_link = !comment['topcomment'] &&
                     ($user && ($user['id'].to_i == comment['user_id'].to_i)) &&
                     (comment['ctime'].to_i > (Time.now.to_i - CommentEditTime))
  end

  def is_editable?(news)
    $user and ($user['id'].to_i == news['user_id'].to_i) and (news['ctime'].to_i > (Time.now.to_i - NewsEditTime))
  end

  def is_logged_in?
    !$user.nil?
  end

  def get_domain(news)
    d = news_domain(news)
    d.nil? ? '' : "en #{d}"
  end

  def news_url(news)
    d = news_domain(news)
    d.nil? ? "/news/#{news["id"]}" : news['url']
  end

  def debug_code(news)
    if params and params[:debug] and $user and user_is_admin?($user)
      "score: #{news["score"].to_s} rank: #{compute_news_rank(news).to_s}"
    end
  end

  def entities(s)
    s.nil? ? '' : CGI::escapeHTML(s)
  end

  def unentities(s)
      CGI::unescapeHTML(s)
  end

  def urlencode(s)
      CGI::escape(s)
  end

  def urldecode(s)
      CGI::unescape(s)
  end
end

###############################################################################
# Comments
###############################################################################

# This function has different behaviors, depending on the arguments:
#
# 1) If comment_id is -1 insert a new comment into the specified news.
# 2) If comment_id is an already existing comment in the context of the
#    specified news, updates the comment.
# 3) If comment_id is an already existing comment in the context of the
#    specified news, but the comment is an empty string, delete the comment.
#
# Return value:
#
# If news_id does not exist or comment_id is not -1 but neither a valid
# comment for that news, nil is returned.
# Otherwise an hash is returned with the following fields:
#   news_id: the news id
#   comment_id: the updated comment id, or the new comment id
#   op: the operation performed: "insert", "update", or "delete"
#
# More informations:
#
# The parent_id is only used for inserts (when comment_id == -1), otherwise
# is ignored.
def insert_comment(news_id,user_id,comment_id,parent_id,body)
    news = get_news_by_id(news_id)
    return false if !news
    if comment_id == -1
        if parent_id.to_i != -1
            p = Comments.fetch(news_id,parent_id)
            return false if !p
        end
        comment = {"score" => 0,
                   "body" => body,
                   "parent_id" => parent_id,
                   "user_id" => user_id,
                   "ctime" => Time.now.to_i,
                   "up" => [user_id.to_i] };
        comment_id = Comments.insert(news_id,comment)
        return false if !comment_id
        $r.hincrby("news:#{news_id}","comments",1);
        $r.zadd("user.comments:#{user_id}", Time.now.to_i, news_id.to_s+"-"+comment_id.to_s);
        # increment_user_karma_by(user_id,KarmaIncrementComment)
        if p and $r.exists("user:#{p['user_id']}")
            $r.hincrby("user:#{p['user_id']}","replies",1)
        end
        return {
            "news_id" => news_id,
            "comment_id" => comment_id,
            "op" => "insert"
        }
    end

    # If we reached this point the next step is either to update or
    # delete the comment. So we make sure the user_id of the request
    # matches the user_id of the comment.
    # We also make sure the user is in time for an edit operation.
    c = Comments.fetch(news_id,comment_id)
    return false if !c or c['user_id'].to_i != user_id.to_i
    return false if !(c['ctime'].to_i > (Time.now.to_i - CommentEditTime))

    if body.length == 0
        return false if !Comments.del_comment(news_id,comment_id)
        $r.hincrby("news:#{news_id}","comments",-1);
        return {
            "news_id" => news_id,
            "comment_id" => comment_id,
            "op" => "delete"
        }
    else
        update = {"body" => body}
        update = {"del" => 0} if c['del'].to_i == 1
        return false if !Comments.edit(news_id,comment_id,update)
        return {
            "news_id" => news_id,
            "comment_id" => comment_id,
            "op" => "update"
        }
    end
end

# Compute the comment score
def compute_comment_score(c)
    upcount = (c['up'] ? c['up'].length : 0)
    downcount = (c['down'] ? c['down'].length : 0)
    upcount-downcount
end

# Given a string returns the same string with all the urls converted into
# HTML links. We try to handle the case of an url that is followed by a period
# Like in "I suggest http://google.com." excluding the final dot from the link.
def urls_to_links(s)
    urls = /((https?:\/\/|www\.)([-\w\.]+)+(:\d+)?(\/([\w\/_\.\-\%]*(\?\S+)?)?)?)/
    s.gsub(urls) {
        if $1[-1..-1] == '.'
            url = $1.chop
            '<a href="'+url+'">'+url+'</a>.'
        else
            '<a href="'+$1+'">'+$1+'</a>'
        end
    }
end

def render_comments_for_news(news_id,root=-1)
  html = ""
  user = {}
  news = get_news_by_id(params["news_id"])
  Comments.render_comments(news_id,root) {|c|
      user[c["id"]] = get_user_by_id(c["user_id"]) if !user[c["id"]]
      user[c["id"]] = DeletedUser if !user[c["id"]]
      u = user[c["id"]]
      html << erb( :comment, :locals => {:news => news, :comment => c, :user => user[c['id']], :layout => false})
  }
  html
end

def vote_comment(news_id,comment_id,user_id,vote_type)
  user_id = user_id.to_i
  comment = Comments.fetch(news_id,comment_id)
  return false if !comment
  varray = (comment[vote_type.to_s] or [])
  return false if varray.index(user_id)
  varray << user_id
  return Comments.edit(news_id,comment_id,{vote_type.to_s => varray})
end

# Get comments in chronological order for the specified user in the
# specified range.
def get_user_comments(user_id,start,count)
  numitems = $r.zcard("user.comments:#{user_id}").to_i
  ids = $r.zrevrange("user.comments:#{user_id}",start,start+(count-1))
  comments = []
  ids.each{|id|
    news_id,comment_id = id.split('-')
    comment = Comments.fetch(news_id,comment_id)
    comments << comment if comment
  }
  [comments,numitems]
end

###############################################################################
# Utility functions
###############################################################################

# Given an unix time in the past returns a string stating how much time
# has elapsed from the specified time, in the form "2 hours ago".
def str_elapsed(t)
    seconds = Time.now.to_i - t
    return "recién" if seconds < 60
    return pluralize(seconds/60,    'minuto', 'minutos') if seconds < 3600   # 60*60
    return pluralize(seconds/3600,  'hora',   'horas')   if seconds < 86400  # 60*60*24
    return pluralize(seconds/86400, 'día',    'días')                        # 60 * 60 * 24
end

def pluralize(count, singular, plural)
  "hace #{count || 0} " + ((count == 1 || count =~ /^1(\.0+)?$/) ? singular : (plural || singular.pluralize))
end

# Generic API limiting function
def rate_limit_by_ip(delay,*tags)
    key = "limit:"+tags.join(".")
    return true if $r.exists(key)
    $r.setex(key,delay,1)
    return false
end

# build the bookmarlet
def get_bookmarlet
  "javascript:window.location=%22#{SiteUrl}/submit?u=%22+encodeURIComponent(document.location)+%22&t=%22+encodeURIComponent(document.title)"
end

def get_apisecret
  "var apisecret = '#{is_logged_in? ? $user['apisecret'] : ''}';"
end

def get_path_info
  if (request.path_info == '/')
    return '/latest'
  else
    return "/#{request.path_info.split('/')[1]}"
  end
end

def build_nav
  segments = request.path_info.split('/')
  if segments.length == 0
    yield '/'
  else
    yield segments[1]
  end
end
