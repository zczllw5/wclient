const fs = require('fs');
const lighthouse = require('lighthouse');
const chromeLauncher = require('chrome-launcher');

var hostsArr = [];

function get_hosts(arr){
    var hosts = "google.com youtube.com sina.com.cn canva.com google.com.hk google.com.br blogger.com google.co.in google.co.jp google.de walmart.com";
    arr = hosts.split(" ");
    return arr;
}

hostsArr = get_hosts(hostsArr);

function concat_http(arr){
    for (let i = 0; i < arr.length; i++) {
        arr[i] = "https://www.".concat(arr[i]);
    }
    return arr;
}

hostsArr = concat_http(hostsArr);

async function use_lighthouse(url){
    console.log("url: ", url);
    const chrome = await chromeLauncher.launch({chromeFlags: ['--headless']});
    const options = {logLevel: 'info', output: 'json', onlyCategories: ['performance'], port: chrome.port};
    const runnerResult = await lighthouse(url, options);

    const reportHtml = runnerResult.report;
    fs.writeFileSync('lhreport.json', reportHtml);

    fcp = await runnerResult.lhr.audits["first-contentful-paint"].score;
    lcp = await runnerResult.lhr.audits["largest-contentful-paint"].score;
    tti = await runnerResult.lhr.audits["interactive"].score;
    //console.log('lhr.audits.FCP: ', fcp);
    //console.log('lhr.audits.LCP: ', lcp);
    //console.log('lhr.audits.TTI: ', tti);

    await chrome.kill();
    return [fcp,lcp,tti];
};

async function* asyncGenerator() {
    let j = 0;
    while (j < 100) {
        yield use_lighthouse(hostsArr[3]);
        j++;
    }
}
(async () => {
    var fcp_sum =0;
    var lcp_sum = 0; 
    var tti_sum = 0;
    for await (var res of asyncGenerator()) {

        fcp_sum += res[0];
        lcp_sum += res[1];
        tti_sum += res[2];
        console.log("[fcp,lcp,tti]: ", res[0], res[1], res[2]);
        console.log("fcp_sum,lcp_sum,tti-sum: ", fcp_sum,  lcp_sum, tti_sum);
    }
})();

// try {
//     fs.writeFileSync('/0-RTT/test.txt', fcp);
//     //file written successfully
// } catch (err) {
//     console.error(err);
// }
