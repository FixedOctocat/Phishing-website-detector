chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
    let url = tabs[0].url;
    document.getElementById("resp").innerHTML = "Статус обрабатывается..."
    $.post('http://10.20.1.43/api/check_url', {'url':url}, function (data) {
    	let status = "<font color='purple'>Статус сайта неизвестен</font>";
    	if (data['status'] == 1)
    		status = "<font color='green'>Доверенный сайт</font>";
    	else if (data['status'] == -1)
    		status = "<font color='crimson'>Фишинговый сайт</font>";
    	document.getElementById("resp").innerHTML = status;
    });
});
