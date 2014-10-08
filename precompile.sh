echo "precompiling assets such as javascript files"
rake assets:precompile
chown www-data:www-data ./app/assets/javascripts/analytics.js 
chown -R www-data:www-data ./tmp/
