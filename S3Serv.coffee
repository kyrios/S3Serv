#
# S3Serv.coffee
# Copyright (c) 2013 Thorsten Philipp <kyrios@kyri0s.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in the 
# Software without restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the
# following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

express = require('express')
colors = require('colors')
path = require('path')
crypto = require('crypto')
app = express()


LISTENPORT = 3001



help = () ->
    console.log('Required parameters are missing'.red)
    console.log('')
    console.log('Usage:')
    console.log(process.argv[0] + ' ' + process.argv[1] + ' <WEBROOT> <AWSKEY> <AWSSECRET> [LISTENPORT]')
    console.log('')
    console.log('WEBROOT:\tThe local folder that should be served.')
    console.log('AWSKEY:\t\tThe AWS Key')
    console.log('AWSSECRET:\tMatching Secret for your AWS Key')
    console.log('LISTENPORT (optional):\tA port to listen on. (Default:' + LISTENPORT + ')')
    process.exit()


if(process.argv.length < 4)
    help()


# PARAM1 ==> BACKEND URL TO AIDA HOST
WEBROOT = path.resolve(process.argv[2]);
AWSKEY = process.argv[3];
AWSSECRET = process.argv[4]

if(process.argv[5])
	LISTENPORT = process.argv[5]


validateFreshness = (req, res, next) ->
	
	expires = parseInt(req.query.Expires)
	now = new Date;
	if not expires
		res.send(400, 'Your request doesn\'t contain an Expires parameter and therefore looks invalid')
	
	else if expires < parseInt( now.getTime() /  1000 )
		res.send(403, 'The requested URL is no longer valid. Your link expired')

	else
		next()


validateSignature = (awskey, awssecret) ->
	return (req, res, next) ->

		hostParts = req.headers.host.split(':') # hostname and maybe port

		stringToSign = 'GET\n\n\n'
		stringToSign += req.query.Expires
		stringToSign += '\n'
		stringToSign += '/' + hostParts[0] + req._parsedUrl.pathname
		stringToSign += stripAWSKeys(req._parsedUrl.search)


		ourSignature = crypto.createHmac('sha1', awssecret).update(stringToSign).digest('base64')
		theirSignature = req.query.Signature.replace(/\x20/g,'+')
		if(ourSignature == theirSignature)
			next()
		else
			res.send(403, 'Signature wrong')


stripAWSKeys = (queryString) ->
	queryParts = queryString.split('&AWSAccessKeyId')
	return(queryParts[0])



app.use(express.logger())
app.use(validateFreshness)
app.use(validateSignature(AWSKEY,AWSSECRET))
app.use(express.static(WEBROOT))
app.use (err, req, res, next) ->
  console.error(err.stack);
  res.send(500, 'Something broke!')

app.listen(LISTENPORT)

console.log('Listening on port\t'.bold + LISTENPORT.toString().blue)
console.log('Serving files from\t'.bold + WEBROOT.toString().blue)

