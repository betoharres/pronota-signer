const express = require('express')
const bodyParser = require('body-parser')
const sign = require('./mgt.js')
const app = express()

app.set('port', (process.env.PORT || 5000))
app.use(bodyParser.json())

app.post('/', function(req, res) {
  const { xml, certificate, pass } = req.body
  const xmlSigned = sign.sign(xml, certificate, pass)
  res.send(xmlSigned)
})

app.listen(app.get('port'), function() {
  console.log('App runnning at port', app.get('port'))
})

