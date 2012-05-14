# encoding: UTF-8
# Copyright 2011 Salvatore Sanfilippo. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SALVATORE SANFILIPPO ''AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
# NO EVENT SHALL SALVATORE SANFILIPPO OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are
# those of the authors and should not be interpreted as representing official
# policies, either expressed or implied, of Salvatore Sanfilippo.

require 'app_config'
require 'rubygems'
require 'date'
require 'hiredis'
require 'redis'
require 'sinatra'
require 'json'
require 'digest/sha1'
require 'digest/md5'
#require 'page'
require 'cgi'
require 'comments'
require 'pbkdf2'
require 'openssl' if UseOpenSSL
require 'utils'

Version = "0.9.2"

before do
    $r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r
    #H = HTMLGen.new if !defined?(H)
    if !defined?(Comments)
        Comments = RedisComments.new($r,"comment",proc{|c,level|
            c.sort {|a,b|
                ascore = compute_comment_score a
                bscore = compute_comment_score b
                if ascore == bscore
                    # If score is the same favor newer comments
                    b['ctime'].to_i <=> a['ctime'].to_i
                else
                    # If score is different order by score.
                    # FIXME: do something smarter favouring newest comments
                    # but only in the short time.
                    bscore <=> ascore
                end
            }
        })
    end
    $user = nil
    auth_user(request.cookies['auth'])
    increment_karma_if_needed if $user
end

get '/' do
  get_news(0)
end

get '/top' do
  show_top_news(0, 'Notas más votadas')
end

get '/top/:start' do
  show_top_news(params[:start].to_i, 'Notas más votadas')
end

get '/latest' do
  get_news(0)
  #redirect '/latest/0'
end

get '/latest/:start' do
  get_news(params[:start].to_i)
end

def show_top_news(start, title)
  news, numitems = get_top_news(start)
  pager = -1

  if (start+NewsPerPage) < numitems
    pager = start+NewsPerPage
  end

  erb :index, :locals => {:news => news, :pager => pager, :title => title}
end

def get_news(start, title=nil)
  news, numitems = get_latest_news(start,NewsPerPage)

  pager = -1
  if (start+NewsPerPage) < numitems
    pager = start+NewsPerPage
  end

  erb :index, :locals => {:news => news, :pager => pager, :title => title}
end


get '/rss' do
  content_type 'text/xml', :charset => 'utf-8'
  news,count = get_latest_news
  erb :rss, :layout => false, :locals => {:news => news, :count => count}
end

get '/feed' do
  content_type 'text/xml', :charset => 'utf-8'
  news,count = get_latest_news

  erb :rss, :layout => false, :locals => {:news => news, :count => count}
end

get '/acerca' do
  erb :acerca, :locals => {:title => 'acerca'}
end

get '/search' do
  erb :search, :locals => {:title => 'search'}
end


get '/saved/:start' do
    redirect "/login" if !$user
    start = params[:start].to_i
    news,numitems = get_saved_news($user['id'],start,NewsPerPage)

    pager = -1
    if (start+NewsPerPage) < numitems
      pager = start+NewsPerPage
    end

    erb :saved_news, :locals => {:title => 'Noticias Guardadas', :news => news, :pager => pager}
end

get '/usercomments/:username/:start' do
    start = params[:start].to_i
    user = get_user_by_username(params[:username])
    halt(404,"El usuario no existe") if !user
    comments, numitems = get_user_comments(user['id'],start,NewsPerPage)

    pager = -1
    if (start+NewsPerPage) < numitems
      pager = start+NewsPerPage
    end

    erb :usercomments, :locals => {:title => "Comentarios de #{entities(user['username'])}",
                                   :comments => comments,
                                   :user => user,
                                   :pager => pager
                                  }

end

get '/replies' do
    redirect "/login" if !$user
    comments,count = get_user_comments($user['id'],0,SubthreadsInRepliesPage)
    erb :replies, :locals => {:comments => comments, :title =>'Tus comentarios'}
end

get '/login' do
  erb :login, :locals => {:title => 'Formulario de Ingreso'}
end

get '/submit' do
  redirect "/login" if !$user
  erb :submit, :locals => {:title => 'Enviar Noticias'}
end

get '/logout' do
  if $user and check_api_secret
      update_auth_token($user["id"])
  end
  redirect "/"
end

get "/news/:news_id" do
  news = get_news_by_id(params["news_id"])
  halt(404,"404 - Esta noticias no existe.") if !news
  # Show the news text if it is a news without URL.
  if !news_domain(news)
      c = {
          "body" => news_text(news),
          "ctime" => news["ctime"],
          "user_id" => news["user_id"],
          "thread_id" => news["id"],
          "topcomment" => true
      }
      user = get_user_by_id(news["user_id"]) || DeletedUser
      top_comment = erb(:comment, :locals => {:news => news, :user => user, :comment => c}, :layout => false)
  else
    top_comment = ''
  end

  erb :show, :locals => {:title => entities(news['title']), :news => news, :comment => c, :top_comment => top_comment, :user => user }
end

get "/comment/:news_id/:comment_id" do
  news = get_news_by_id(params["news_id"])
  halt(404,"404 - Esta noticia no existe.") if !news
  comment = Comments.fetch(params["news_id"],params["comment_id"])
  halt(404,"404 - Este comentario no existe.") if !comment
  erb :comment_news, :locals => {:news => news, :comment => comment, :title => "Comentarios para: #{news['title']}"}
end

def render_comment_subthread(comment,sep="")
  user = get_user_by_id(comment["user_id"]) || DeletedUser
  erb :single_comment, :locals => {:comment => comment, :user => user, :sep => sep}
end

get "/reply/:news_id/:comment_id" do
  redirect "/login" if !$user
  news = get_news_by_id(params["news_id"])
  halt(404,"404 - Esta noticia no existe.") if !news
  comment = Comments.fetch(params["news_id"],params["comment_id"])
  halt(404,"404 - Este comentario no existe.") if !comment
  user = get_user_by_id(comment["user_id"]) || DeletedUser

  erb :reply, :locals => {:news => news, :comment => comment, :user => user, :title => "Responder a: #{news['title']}" }
end

get "/editcomment/:news_id/:comment_id" do
  redirect "/login" if !$user
  news = get_news_by_id(params["news_id"])
  halt(404,"404 - Esta noticia no existe.") if !news
  comment = Comments.fetch(params["news_id"],params["comment_id"])
  halt(404,"404 - Este comentario no existe.") if !comment
  user = get_user_by_id(comment["user_id"]) || DeletedUser
  halt(500,"Permiso denegado.") if $user['id'].to_i != user['id'].to_i

  erb :edit_comment, :locals => {:news => news, :comment => comment, :user => user, :title => 'Editar comentario' }
end

get "/editnews/:news_id" do
  redirect "/login" if !$user
  news = get_news_by_id(params["news_id"])
  halt(404,"404 - Esta noticia no existe.") if !news
  halt(500,"Permiso denegado.") if $user['id'].to_i != news['user_id'].to_i

  if news_domain(news)
      text = ""
  else
      text = news_text(news)
      news['url'] = ""
  end

  erb :edit_news, :locals => {:news => news, :text => text, :title => 'Editar Noticia'}
end

get "/user/:username" do
  user = get_user_by_username(params[:username])
  halt(404,"El usuario no existe") if !user
  posted_news, posted_comments = $r.pipelined {
    $r.zcard("user.posted:#{user['id']}")
    $r.zcard("user.comments:#{user['id']}")
  }
  owner = $user && ($user['id'].to_i == user['id'].to_i)
  erb :user, :locals => { :user => user, :owner => owner, :title => entities(user['username']),
                          :posted_news => posted_news, :posted_comments => posted_comments }
end

get "/user/:username/rss" do
  user = get_user_by_username(params[:username])
  halt(404,"El usuario no existe") if !user
  content_type 'text/xml', :charset => 'utf-8'
  news,count = get_user_news(user['id'])

  erb :rss, :layout => false, :locals => {:news => news, :count => count}
end



###############################################################################
# API implementation
###############################################################################

post '/api/logout' do
    content_type 'application/json'
    if $user and check_api_secret
        update_auth_token($user["id"])
        return {:status => "ok"}.to_json
    else
        return {
            :status => "err",
            :error => "Credenciales erroneas o códig de API inválido."
        }.to_json
    end
end

get '/api/login' do
    content_type 'application/json'
    if (!check_params "username","password")
        return {
            :status => "err",
            :error => "Se debe ingrear un usuario y clave."
        }.to_json
    end
    auth,apisecret = check_user_credentials(params[:username], params[:password])
    if auth
        return {
            :status => "ok",
            :auth => auth,
            :apisecret => apisecret
        }.to_json
    else
        return {
            :status => "err",
            :error => "No concuardan el nombre de usuario y clave."
        }.to_json
    end
end

post '/api/create_account' do
    content_type 'application/json'
    if (!check_params "username","password")
        return {
            :status => "err",
            :error => "Se debe ingrear un usuario y clave."
        }.to_json
    end
    if params[:password].length < PasswordMinLength
        return {
            :status => "err",
            :error => "La clave es muy corta. Longitud mínima: #{PasswordMinLength}"
        }.to_json
    end
    auth,errmsg = create_user(params[:username],params[:password])
    if auth
        return {:status => "ok", :auth => auth}.to_json
    else
        return {
            :status => "err",
            :error => errmsg
        }.to_json
    end
end

post '/api/submit' do
    content_type 'application/json'
    return {:status => "err", :error => "No autenticado."}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "Error de clave en el formulario."}.to_json
    end

    # We can have an empty url or an empty first comment, but not both.
    if (!check_params "title","news_id",:url,:text) or
                               (params[:url].length == 0 and
                                params[:text].length == 0)
        return {
            :status => "err",
            :error => "Por favor ingrese un Título y una URL o un texto."
        }.to_json
    end
    # Make sure the URL is about an acceptable protocol, that is
    # http:// or https:// for now.
    if params[:url].length != 0
        if params[:url].index("http://") != 0 and
           params[:url].index("https://") != 0
            return {
                :status => "err",
                :error => "Solo se aceptan URL con http:// o https://"
            }.to_json
        end
    end
    if params[:news_id].to_i == -1
        if submitted_recently
            return {
                :status => "err",
                :error => "Ya envió una noticia recientemente, "+
                "por favor espere #{allowed_to_post_in_seconds} segundos."
            }.to_json
        end
        if is_duplicated?(params[:url])
            return {
              :status => "err",
              :error => "Esa noticia ya fue ingresada."
            }.to_json
        end
        news_id = insert_news(params[:title],params[:url],params[:text], $user["id"])
    else
        news_id = edit_news(params[:news_id],params[:title],params[:url], params[:text],$user["id"])
        if !news_id
            return {
                :status => "err",
                :error => "Parámetors inválidos, la noticias es muy vieja para ser modificada o la URL de la noticias ya fue compartida"
            }.to_json
        end
    end
    return  {
        :status => "ok",
        :news_id => news_id.to_i
    }.to_json
end

post '/api/delnews' do
    content_type 'application/json'
    return {:status => "err", :error => "No autenticado."}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "API secret error."}.to_json
    end
    if (!check_params "news_id")
        return {
            :status => "err",
            :error => "Por favor ingreso un título."
        }.to_json
    end
    if del_news(params[:news_id],$user["id"])
        return {:status => "ok", :news_id => -1}.to_json
    end
    return {:status => "err", :error => "Noticias muy vieja o ID erroneo"}.to_json
end

post '/api/votenews' do
    content_type 'application/json'
    return {:status => "err", :error => "Debes estar conectado para participar."}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "API secret error."}.to_json
    end
    # Params sanity check
    if (!check_params "news_id","vote_type") or (params["vote_type"] != "up" and
                                                 params["vote_type"] != "down")
        return {
            :status => "err",
            :error => "No se encontró el ID de la noticias o tipo de voto inválido."
        }.to_json
    end
    # Vote the news
    vote_type = params["vote_type"].to_sym
    karma,error = vote_news(params["news_id"].to_i,$user["id"],vote_type)
    if karma
        return { :status => "ok" }.to_json
    else
        return { :status => "err",
                 :error => error }.to_json
    end
end

post '/api/postcomment' do
    content_type 'application/json'
    return {:status => "err", :error => "No autenticado."}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "API secret error."}.to_json
    end
    # Params sanity check
    if (!check_params "news_id","comment_id","parent_id",:comment)
        return {
            :status => "err",
            :error => "Missing news_id, comment_id, parent_id, or comment parameter."
        }.to_json
    end
    info = insert_comment(params["news_id"].to_i,$user['id'],
                          params["comment_id"].to_i,
                          params["parent_id"].to_i,params["comment"])
    return {
        :status => "err",
        :error => "Noticia inválida, comentario o tiempo de edición expirado."
    }.to_json if !info
    return {
        :status => "ok",
        :op => info['op'],
        :comment_id => info['comment_id'],
        :parent_id => params['parent_id'],
        :news_id => params['news_id']
    }.to_json
end

post '/api/updateprofile' do
    content_type 'application/json'
    return {:status => "err", :error => "No autenticado"}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "API secret error"}.to_json
    end
    if !check_params(:about, :email, :password)
        return {:status => "err", :error => "Faltan parámetros."}.to_json
    end
    if params[:password].length > 0
        if params[:password].length < PasswordMinLength
            return {
                :status => "err",
                :error => "Clave muy corta. "+
                          "Longitud mínima: #{PasswordMinLength}"
            }.to_json
        end
        $r.hmset("user:#{$user['id']}","password",
            hash_password(params[:password],$user['salt']))
    end
    $r.hmset("user:#{$user['id']}",
        "about", params[:about][0..4095],
        "email", params[:email][0..255])
    return {:status => "ok"}.to_json
end

post '/api/votecomment' do
    content_type 'application/json'
    return {:status => "err", :error => "Debes estar conectado para participar."}.to_json if !$user
    if not check_api_secret
        return {:status => "err", :error => "API secret error."}.to_json
    end
    # Params sanity check
    if (!check_params "comment_id","vote_type") or
                                            (params["vote_type"] != "up" and
                                             params["vote_type"] != "down")
        return {
            :status => "err",
            :error => "Falta el ID de la noticias o el tipo de votación es inválida."
        }.to_json
    end
    # Vote the news
    vote_type = params["vote_type"].to_sym
    news_id,comment_id = params["comment_id"].split("-")
    if vote_comment(news_id.to_i,comment_id.to_i,$user["id"],vote_type)
        return { :status => "ok", :comment_id => params["comment_id"] }.to_json
    else
        return { :status => "err",
                 :error => "Parámetros inválidos y voto duplicado." }.to_json
    end
end

get  '/api/getnews/:sort/:start/:count' do
    content_type 'application/json'
    sort = params[:sort].to_sym
    start = params[:start].to_i
    count = params[:count].to_i
    if not [:latest,:top].index(sort)
        return {:status => "err", :error => "Parámetro de ordenación inválido"}.to_json
    end
    return {:status => "err", :error => "Contador muy largo"}.to_json if count > APIMaxNewsCount

    start = 0 if start < 0
    getfunc = method((sort == :latest) ? :get_latest_news : :get_top_news)
    news,numitems = getfunc.call(start,count)
    news.each{|n|
        ['rank','score','user_id'].each{|field| n.delete(field)}
    }
    return { :status => "ok", :news => news, :count => numitems }.to_json
end

get  '/api/getcomments/:news_id' do
    content_type 'application/json'
    return {
        :status => "err",
        :error => "Wrong news ID."
    }.to_json if not get_news_by_id(params[:news_id])
    thread = Comments.fetch_thread(params[:news_id])
    top_comments = []
    thread.each{|parent,replies|
        if parent.to_i == -1
            top_comments = replies
        end
        replies.each{|r|
            user = get_user_by_id(r['user_id']) || DeletedUser
            r['username'] = user['username']
            r['replies'] = thread[r['id']] || []
            if r['up']
                r['voted'] = :up if $user && r['up'].index($user['id'].to_i)
                r['up'] = r['up'].length
            end
            if r['down']
                r['voted'] = :down if $user && r['down'].index($user['id'].to_i)
                r['down'] = r['down'].length
            end
            ['id','thread_id','score','parent_id','user_id'].each{|f|
                r.delete(f)
            }
        }
    }
    return { :status => "ok", :comments => top_comments }.to_json
end

