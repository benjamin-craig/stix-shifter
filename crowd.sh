export http_proxy="http://a:a@1.1.1.1:3"
export https_proxy="http://a:a@1.1.1.1:3"
export no_proxy="localhost,127.0.0.0/8,*.local,s3.us-east-1.amazonaws.com"

export STIX_SHIFTER_ENABLE_TRUST_ENV="true"

echo "================CURL================="
curl -v l-location 'https://api.us-2.crowdstrike.com:443/oauth2/token' --header 'accept: application/json' --header 'user-agent: oca_stixshifter_1.0' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=asfd' --data-urlencode 'client_secret=asdf'
echo "================Python Request ==============="
python crowd.py :q!
echo "================Stix Shifter===================="
python main.py transmit crowdstrike "{\"host\":\"api.us-2.crowdstrike.com\"}" "{\"auth\":{\"client_id\":\"asdf\", \"client_secret\":\"asdf\"}}" ping
echo "================Stix Shifter===================="
python main.py transmit stix_bundle "{\"host\":\"https://raw.githubusercontent.com/opencybersecurityalliance/stix-shifter/develop/data/cybox/qradar/qradar_observed_2000.json\"}" "{\"auth\":{}}" ping
