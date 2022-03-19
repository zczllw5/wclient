const fs = require('fs');
const lighthouse = require('lighthouse');
const chromeLauncher = require('chrome-launcher');

var hostsArr = [];

function get_hosts(arr){
    var hosts = "google.com youtube.com tmall.com qq.com baidu.com sohu.com taobao.com facebook.com 360.cn jd.com amazon.com yahoo.com wikipedia.org weibo.com zoom.us sina.com.cn live.com panda.tv zhanqi.tv microsoft.com office.com netflix.com force.com instagram.com canva.com google.com.hk reddit.com csdn.net www.alipay.com myshopify.com bing.com vk.com yahoo.co.jp twitter.com naver.com www.xinhuanet.com linkedin.com yy.com apple.com huanqiu.com adobe.com coinmarketcap.com chaturbate.com amazon.in tianya.cn amazon.co.jp haosou.com ebay.com msn.com 1688.com okezone.com aliexpress.com tiktok.com yandex.ru whatsapp.com dropbox.com twitch.tv indeed.com binance.com tradingview.com mail.ru chase.com wordpress.com cctv.com opensea.io so.com etsy.com imdb.com google.com.br spotify.com blogger.com www.mama.cn google.co.in liputan6.com paypal.com google.co.jp pikiran-rakyat.com alibaba.com freepik.com pornhub.com 6.cn google.de semrush.com ci123.com cnzz.com gome.com.cn www.rednet.cn salesforce.com telegram.org cnblogs.com intuit.com tribunnews.com walmart.com google.fr chatwork.com zendesk.com flipkart.com booking.com pinterest.com ok.ru"; 
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
    while (j < 10) {
        yield use_lighthouse(hostsArr[0]);
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
        console.log("[fcp,lcp,tti]: ", fcp_sum,  lcp_sum, tti_sum);
    }
})();

// try {
//     fs.writeFileSync('/0-RTT/test.txt', fcp);
//     //file written successfully
// } catch (err) {
//     console.error(err);
// }
