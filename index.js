const express = require('express');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const session = require('express-session');
const request = require('request');

const app = express();

OAuth2Strategy.prototype.userProfile = (accessToken, done) => {
	const options = {
		url: process.env.USERINFO_URL,
		headers: {
			'User-Agent': 'request',
			'Authorization': 'Bearer ' + accessToken,
		}
	};

	request(options, (error, response, body) => {
		if (error || response.statusCode !== 200) {
			return done(error);
		}
		const info = JSON.parse(body);
		console.log(info);
		return done(null, {
			id: info.user_id,
			email: info.user_email,
		});
	});
};

passport.serializeUser(function(user, done) {
	done(null, user);
});

passport.deserializeUser(function(user, done) {
	done(null, user);
});

const strategyConfig = {
	authorizationURL: process.env.AUTHORIZATION_URL,
	tokenURL: process.env.TOKEN_URL,
	clientID: process.env.APP_CLIENT_ID,
	callbackURL: "http://127.0.0.1:" + process.env.PORT + "/auth/example/callback",
	scope: 'user.account.readonly offline',
	state: true,
	pkce: true,
} 

if (process.env.APP_CLIENT_SECRET && process.env.APP_CLIENT_SECRET !== "") {
	strategyConfig.clientSecret = process.env.APP_CLIENT_SECRET
}

passport.use(new OAuth2Strategy(strategyConfig,
	(accessToken, refreshToken, profile, done) => {
		const user = {
			accessToken: accessToken,
			refreshToken: refreshToken,
			profile: profile
		};
		done(null, user);
	}
));

app.use(session({ secret: 'SECRET' })); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

app.get('/', (req, res) => {
	res.send(`<html>
<body>
<h1>Welcome to the exemplary OAuth 2.0 Consumer!</h1>
<p>This is an example app which emulates an OAuth 2.0 consumer application. Usually, this would be your web or mobile
		application and would use an <a href="https://oauth.net/code/">OAuth 2.0</a> or <a href="https://oauth.net/code/">OpenID
				Connect</a> library.</p>
<p>This example requests an OAuth 2.0 Access, Refresh, and OpenID Connect ID Token from the OAuth 2.0 Server (Ory
		Hydra).
		To initiate the flow, click the "Authorize Application" button.</p>
<p><a href="/auth/example">Authorize application</a></p>
</body>
</html>`)
})

app.get('/auth/example', passport.authenticate('oauth2'));

app.get('/auth/example/callback',
	passport.authenticate('oauth2', { failureRedirect: '/login' }),
	(req, res) => {
		res.redirect('/auth/profile');
	});

app.get('/auth/profile', (req, res) => {
	res.send(`<html>
<head></head>
<body>
<ul>
		<li>User ID: <code>` + req.user.profile.id + `</code></li>
		<li>User Email: <code>` + req.user.profile.email + `</code></li>
		<li>Access Token: <code>` + req.user.accessToken + `</code></li>
		<li>Refresh Token: <code>` + req.user.refreshToken + `</code></li>
</ul>
<a href="` + process.env.LOGOUT_URL + `">Logout</a>
</body>
</html>`)
})

app.get('/auth/profile', (req, res) => {
	res.status(200).json(req.user);
});

app.listen(process.env.PORT, () => {
	console.log('listening on *:' + process.env.PORT);
});

module.exports = app;
