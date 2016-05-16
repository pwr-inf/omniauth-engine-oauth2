require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Engine < OmniAuth::Strategies::OAuth2

      option :name, "engine_oauth2"

      uid{ raw_info['username'] }

      info do
        {
          name:       raw_info['principal']['name'] + raw_info['principal']['surname'],
          email:      raw_info['principal']['email'],
          nickname:   raw_info['principal']['username'],
          first_name: raw_info['principal']['name'],
          last_name:  raw_info['principal']['surname']
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
