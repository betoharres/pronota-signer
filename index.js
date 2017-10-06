const express = require('express')
const bodyParser = require('body-parser')
const sign = require('./mgt.js')
const app = express()

app.set('port', (process.env.PORT || 5000))
app.use(bodyParser.json())

app.post('/', function(req, res) {
  const { xml, certificate, password } = req.body
  if (xml && certificate && password) {
    const xmlSigned = sign.sign(xml, certificate, password)
    res.send(xmlSigned)
  } else {
    res.status(400)
    res.json({error: 'Empty required attributes. {sign: {xml, certificate, password}}'})
  }
})

app.listen(app.get('port'), function() {
  console.log('App runnning at port', app.get('port'))
})

