const app = require('./api/app');
const port = process.env.PORT || 3000;


app.listen(port, () => {
    console.log(process.env.PORT ? `Example app listening on port ${port}` : `Running on http://localhost:${port}`);
})

