const express = require('express')
const bodyParser = require('body-parser')
const sign = require('./mgt.js')
const app = express()

app.set('port', (process.env.PORT || 5000))
app.use(bodyParser.json())

app.post('/', function(req, res) {
  const xmlSigned = sign.sign(req.body.xml, req.body.certificate, req.body.pass)
  res.send(req.body)
})

app.listen(app.get('port'), function() {
  console.log('App runnning at port', app.get('port'))
})

