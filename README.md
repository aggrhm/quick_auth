# QuickAuth

QuickAuth is a library that provides authentication functionality specifically for Rails APIs. It provides no view logic, but is strictly meant to augment controller and model logic. It is built with the OAuth2 protocol in mind, but extensibly designed to fit future authentication techniques.

Since the logic is included into your own models via Ruby modules, any ORM should work. Work must be done to ensure certain model fields are available. The fields are automatically added for MongoDB (mongoid), and can be added via the included migrations [coming soon] for relational databases.

## Installation

Add this line to your application's Gemfile:

	gem 'quick_auth', github: 'agquick/quick_auth'

And then execute:

	$ bundle install

## Defining Models

The necessary models can be defined anywhere/anyhow you like. They simply must include the proper QuickAuth modules. For the purpose of this documentation, we will assume a Mongoid ORM.

### Client

The *Client* model represents third-party applications requesting access to your API.

	# models/client.rb
	class Client
		include Mongoid::Document
		include QuickAuth::Client

		quick_auth_client_fields_for :mongoid

	end

### Token

The *Token* model represents the access tokens granted to client applications.

	# models/token.rb
	class Token
		include Mongoid::Document
		include QuickAuth::Token

		quick_auth_token_fields_for :mongoid

	end

## Defining Controllers

To define the proper endpoints, you must include the proper module for your protocol strategy. Currently, only OAuth2 has been implemented. To apply, begin by defining your authentication-handling controller. For our purposes, we'll call it *AuthController*.

	# controllers/auth_controller.rb
	class AuthController < ActionController::Base
		include QuickAuth::OAuth2::Endpoints

	end

Now you must add the proper routing.

	# config/routes.rb
	...
	match "auth/token" => "auth#token", :via => :post
	...


## Configuration

Specify your configuration settings in *config/quick_auth.yml*. Here is a sample config file:

	# config/quick_auth.yml

	development:				# add for each deployment environment
		auth_methods:
			- :token
		classes:
			client: Client	# could be Auth::Client, whatever class you created
			token: Token


## Creating Clients

Once everything is configured, you will need a way to register clients. You can build an interface for creating clients, or use the Ruby console for internal clients. The Client class includes a simple method for this called *Client.register*.

	$ rails console
	$> client = Client.register("My First Client")
	$> client.uuid	# your id
	$> client.secret	# your secret

## Obtaining Tokens

The *token* endpoint can be used in conformance with the OAuth2 protocol. It is recommended that you read the [RFC](http://tools.ietf.org/html/rfc6749). Presently only the "Resource Owner Password Credentials Grant" and "Token Refresh" strategies are implemented. The returned token will have the following format.

	{
		"access_token":"2YotnFZFEjr1zCsicMWpAA",
		"token_type":"bearer",
		"expires_in":3600,
		"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
		"example_parameter":"example_value"
	}

### Resource Owner Password Credentials

This strategy is primarily for highly-authorized clients, as it allows the client to accept the username and password of the client directly. See usage below:

	POST /auth/token
		# authentication
		client_id: <your client id>
		client_secret: <your client secret>
		# additional params
		grant_type: "password"
		username: <resource owner username>
		password: <resource owner password>
		scope: <comma separated scope string> (optional)

This will return a token with the syntax of the RFC.

### Refresh Request

This strategy allows a client to quickly update an access token after it has expired.

	POST /auth/token
		# authentication
		client_id: <your client id>
		client_secret: <your client secret>
		# additional params
		grant_type: "refresh_token"
		refresh_token: <token refresh string>
		scope: <comma separated scope string> (optional)

## Using Tokens to Access the API

Now that your API has token support, you need to allow your API controllers to authenticate against the token. To do so, just include the *QuickAuth::Authentication* module.

	# controllers/application_controller.rb
	class ApplicationController < ActionController::Base
		include QuickAuth::Authentication

	end

Note that this module does not perform *any* authorization. All it does is set *current_user*, *current_client*, and *current_token* within your controller scope according to the request Authorization header. It is up to you to perform authorization for your API actions using any method you see fit (I personally use CanCan).

Once the client has obtained a valid access token, the client may use it to access your API. The client should send the token in the *Authorization* header as a *Bearer* token.

	POST /api/post
	Host: server.example.com
	Authorization: Bearer <access token>
