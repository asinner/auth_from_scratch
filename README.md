# README
This is basic application that demonstrates authentication from scratch.
## Getting Started
Create a new app:  
```
$ rails new auth
```
Jump into your app:
```shell
$ cd auth
```
Create a User resource:
```shell
$ rails generate resource User email password_digest
````
* **Note**: The `password_digest` column is used by the `bcrypt` gem.* 
Lets add that gem. Put this in your gemfile:
```ruby
gem 'bcrypt', '~> 3.1.7'
```
Then make sure to run bundle install:
```shell
$ bundle install
```
After this put `has_secure_password` into your `User` model `app/models/user.rb`
```ruby
class User < ActiveRecord::Base
	has_secure_password
end
```
The `has_secure_password` method is added by the `bcrypt` gem. It encrypts your passwords and saves them to the `password_digest` in your database.

Next fill out your `users_controller.rb` in `app/controllers/users_controller.rb`
```ruby
class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)

    if @user.save
      redirect_to @user, notice: 'Thanks for signing up!'
    else
      render :new
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end

  def set_user
    @user = User.find(params[:id])
  end
end
```
* **Note**: checkout the `user_params` method.*
```ruby
def user_params
  params.require(:user).permit(:email, :password, :password_confirmation)
end
```
This permits a `:password_confirmation` attribute to be passed onto the model for use in validation. This is used by `has_secure_password` to confirm that the passwords match.
Next create your views `app/views/users/new.html.erb`:
```erb
<%= form_for @user do |f| %>
	<% if @user.errors.any? %>
		<div>
			<% @user.errors.full_messages.each do |msg| %>
				<p><%= msg %></p>
			<% end %>
		</div>
	<% end %>
	
	<div class='field'>
		<%= f.label :email %>
		<%= f.email_field :email %>
	</div>
	
	<div class='field'>
		<%= f.label :password %>
		<%= f.password_field :password %>
	</div>
	
	<div class='field'>
		<%= f.label :password_confirmation %>
		<%= f.password_field :password_confirmation %>
	</div>
	
	<div>
		<%= f.submit %>
	</div>
<% end %>
```
Notice the `f.password_field :password_confirmation` field.
Now users can sign up with secure passwords.
## Sessions
Next, your users need to be able to log in. We will use sessions for this. Create a sessions resource in your `config/routes.rb` file:
```rb
resources :sessions
```
Great now we've got some routes for sessions:
```shell
 sessions 	 GET    /sessions(.:format)          sessions#index
             POST   /sessions(.:format)          sessions#create
 new_session GET    /sessions/new(.:format)      sessions#new
edit_session GET    /sessions/:id/edit(.:format) sessions#edit
     session GET    /sessions/:id(.:format)      sessions#show
             PATCH  /sessions/:id(.:format)      sessions#update
             PUT    /sessions/:id(.:format)      sessions#update
             DELETE /sessions/:id(.:format)      sessions#destroy
```
We'll use `new_session` as our sign in path. Add a 'Sign In' link to your `app/views/layouts/application.html.erb`:
```erb
<%= link_to 'Sign In', new_session_path %>
```
Next create a login form at `app/views/sessions/new.html.erb`:
```erb
<%= form_tag sessions_path do %>
	<div>
		<%= label_tag :email %>
		<%= email_field_tag :email %>
	</div>
	
	<div>
		<%= label_tag :password %>
		<%= password_field_tag :password %>
	</div>
	
	<div>
		<%= submit_tag %>
	</div>
<% end %>
```
* **Note**: the use of the `form_tag` instead of `form_for`. You aren't dealing with an actual object, so `form_tag` will create a form without needing an object to reference. Pass in the `sesions_path` to `form_tag` as if were posting a new object.*
Next let's check out the `sessions#create`
```ruby
def create
  user = User.find_by_email(params[:email])
  if user && user.authenticate(params[:password])
    session[:user_id] = user.id
    redirect_to root_url, notice: 'Logged in'
  else
    flash.now[:error] = 'Invalid email/password'
    render :new
  end
end
```
The first thing we do here is try to find a `User` object with the email param and assign it to a `user` variable:
```ruby
user = User.find_by_email(params[:email])
```
Then we check if the password that was entered matches the password that belongs to the `user` that was found.
```ruby
if user && user.authenticate(params[:password])
# ...
```
The `user.authenticate` method is added by the `Bcrypt` gem. What it does is checks that the string that gets passed to matches the `passwords_digest` column in the database.
If it does we set the `:user_id` key in the session to store the `user.id`. Additionally we redirect to the `root_url`
```ruby
if user && user.authenticate(params[:password])
  session[:user_id] = user.id
  redirect_to root_url, notice: 'Logged in'
else
  flash.now[:error] = 'Invalid email/password'
  render :new
end
```
* **Note**: that if the authentication fails (meaing the passwords don't match), we simply `render :new` to show the log in form again.*
Great now users can log out. Now we will add some functionality to log them out.
Add in a logout link to your `app/views/layouts/application.html.erb`:
```erb
<%= link_to 'Logout', session_path('current'), method: :delete %>
```
* **Note**: The individual resource path `session_path` expects an object to passed so it can use the `id` in the url. example: `/sessions/1`. However we aren't dealing with an actual object here so anything can be passed to `session_path()`*.
Lets check out the `destroy` action in the `SessionsControlle.rb` file to see the logout process.
```ruby
def destroy
  session[:user_id] = nil
  redirect_to root_url, notice: 'Logged out'
end
```
To log a user out we simply set the `session[:user_id]` key to `nil`. After that we `redirect_to` the path we want and flash a log out message.
Great. Now we need a way of checking for a logged in user. We could check for session[:user] in our controllers, but there's a better way. Put this into your `ApplicationController.rb`:
```ruby
class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def current_user
    @current_user ||= User.find(session[:user_id]) if session[:user_id]
  end

  helper_method :current_user

  def authorize
    redirect_to login_url, alert: 'Not authorized' if current_user.nil?
  end
end
```
The `current_user` method checks the `session[:user_id]` for us and returns a `User` object if one is found using the `:user_id` stored in the session. 
The `||=` (double equals) operator checks to see if @current_user is `nil` and if so then assigns it the `User` object returned by `User.find(sesion[:user_id])`.
You can make the `current_user` method availabel to all of your controllers by adding
```ruby
helper_method :current_user
```
Now lets update our `app/views/layouts/application.html.erb` file to use the current method.
```erb
<% if current_user %>
	<div>
		You are logged in as <%= current_user.email %> |
		<%= link_to 'Log out', logout_path('current'), method: :delete %>
	</div>
<% else %>
	<!-- Sign up link -->
	<%= link_to 'Sign up', signup_path %>
	<%= link_to 'Sign in', login_path %>
<% end %>
````
This only shows a logout link if a user is logged in, otherwise it displays a sign in and sign up links if not. 
Great. Now lets check out the authorize method in the `app/controllers/application_controller.rb`:
```ruby
def authorize
  redirect_to login_url, alert: 'Not authorized' if current_user.nil?
end
```
This will redirect any user if they are not signed in. You can use this `authorize` method in before actions to only users who are signed in to access certain actions.
An example would be as follows:
```ruby
class ArticlesController < ApplicationController
  before_action :authorize, only: [:index]

  def index
    @articles = Article.all
  end
end
```
This runs the `authorize` method before every action listed in the array `only: [:index]`.

## Sources
Followed the screencast at http://www.railscasts.com/episodes/250 