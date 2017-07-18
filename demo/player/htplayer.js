        

        function HaitouPlayer(config) {

            const WAITTIME = 30000;
            const WAITFORPLAY = 500;
            const FIRSTPLAYERELEMENTID = 'htp_first'
            const SECONDPLAYERELEMENTID = 'htp_second'


            var realWaitTime = WAITTIME;

            var mConfig = {
                width : 580,
                height : 433,
                backcolor : "#FFFFFF",
                stretching : "uniform",
                primary: 'flash',
                rtmp: {
                    reconnecttime: 5
                },
                file : "rtmp://cdn4.haitou.cc/xjh/test",
                ak : "f13fd2d2dda045f5b9db725095b56bd6",
                autoStart : false,
                repeat : false,
                volume : 100,
                controls : "over"
            };

            for(ckey in config) {
                if(ckey == 'waittime') {
                    realWaitTime = config[key];
                }else {
                    mConfig[ckey] = config[ckey];    
                }
            }

            var waitTimer;
            var currentPlayer;
            
            
            var positionCallBack;
            var startTime = 0;
            var lastTime = -1;


            function buildPlayer(containerId) {
                var player = cyberplayer(containerId).setup(mConfig);
                player.on('time',function(data){
                    //console.log('time:' + data.position);
                        if(startTime == 0) {
                            startTime = currentPlayer.getPosition();
                        }

                        var currentTime = Math.floor(currentPlayer.getPosition() - startTime);
                        if(lastTime != currentTime) {
                            if(typeof positionCallBack === 'function') {
                                positionCallBack(currentTime);                            
                            }
                        }
                        lastTime = currentTime;
                })
                return player;
            }

            init();

            function tryToBuildElement(elementName,defaultName) {
                if(typeof elementName === 'string') {
                    defaultName = elementName;
                }
                var element = document.getElementById(defaultName);
                if(!element) {
                    var elemDiv = document.createElement('div');
                    elemDiv.id = defaultName;
                    document.body.appendChild(elemDiv);
                }
                return defaultName;
            }

            function init() {
                var player = buildPlayer(tryToBuildElement(mConfig[FIRSTPLAYERELEMENTID],FIRSTPLAYERELEMENTID));
                var player1 = buildPlayer(tryToBuildElement(mConfig[SECONDPLAYERELEMENTID],SECONDPLAYERELEMENTID));
                player.on('play', function(){
                    currentPlayer = player; 
                    doWork(player1);
                });
                player1.on('play', function(){
                    currentPlayer = player1; 
                    doWork(player);
                });
                player.on('ready',function(data) {
                    console.log('ready');
                    player.play();
                });
            }

            function doWork(targetPlayer) {
                if(targetPlayer.getState() === 'playing') {
                    targetPlayer.pause();
                }
                waitTimer = setTimeout(function(){
                    tryStarPlayer(targetPlayer);
                },realWaitTime);
            }

            function tryStarPlayer(targetPlayer) {
                if(targetPlayer.getState() === 'idle') {
                    targetPlayer.play();
                }else if(targetPlayer.getState() === 'paused'){
                    targetPlayer.play();
                    var timer = setInterval(function() {
                        //console.log('try play 0')
                        if(targetPlayer.getState() === 'playing') {
                         clearInterval(timer); 
                         return;
                     }
                     targetPlayer.play();
                 },WAITFORPLAY);
                }
            }

            this.play = function() {
                tryStarPlayer(currentPlayer);
            }

            this.pause = function() {
                if(currentPlayer.getState() == 'playing') {
                    currentPlayer.pause();
                    clearTimeout(waitTimer);
                }
            }
            this.getPosition = function() {
                return currentPlayer.getPosition();
            }

            this.setTimeListener = function(callback) {
                positionCallBack = callback;
                console.log('set callback:' + positionCallBack)
            }

        }