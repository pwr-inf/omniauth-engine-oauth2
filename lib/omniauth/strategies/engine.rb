require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Engine < OmniAuth::Strategies::OAuth2
      option :token_params, {
        :parse          => :json
      }

      uid{ raw_info['username'] }

      info do
        {
          :name => raw_info['principal']['first_name']
          :email => raw_info['principal']['email']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/user').parsed
      end

      
    end
  end
end

OmniAuth.config.add_camelization "engine", "Engine"
