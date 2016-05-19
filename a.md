#运营商接入IP修改方法
##登录PSTN GATEWAY服务器

	user：wecopr@CNSZ044506（10.35.219.172）
	password：Paixxxxxxxxxxxxxxxxxxxxxxxxxx##修改运营商网关

1.	cd /etc/freeswitch/dialplan2.	vi public.xml3.	修改对应的ip就好。4.	保存 public.xml5.	执行进入fs_cli 进入freeswitch 控制台6.	执行reloadxml   生效修改配置其他命令：打开sip跟踪：sofia global siptrace on修改inte
##样例

修改public.xml中的**180.167.67.243**地址
`<action application="set" data="dialstring=sofia/internal/$1@180.167.67.243;fs_path=sip:172.28.50.243;transport=udp"/>
     </condition>
`



~~~freeswitch
<include>
  <context name="public">

    <extension name="unloop">
      <condition field="${unroll_loops}" expression="^true$"/>
      <condition field="${sip_looped_call}" expression="^true$">
               <action application="deflect" data="${destination_number}"/>
      </condition>
    </extension>

  <!-- this is for odd tail number -->
    <extension name="sm_dialstring_choice13579_mobile" continue="true">
      <condition field="destination_number" expression="^90300800[03](\d*[13579])$">
       <action application="set" data="dialstring=sofia/internal/$1@117.185.44.170;fs_path=sip:172.28.50.243;transport=udp"/>
      </condition>
    </extension>
    <extension name="sm_dialstring_choice13579_telcom" continue="true">
      <condition field="destination_number" expression="^90300800[1](\d*[13579])$">
       <action application="set" data="dialstring=sofia/internal/$1@180.167.67.243;fs_path=sip:172.28.50.243;transport=udp"/>
     </condition>
    </extension>
    <extension name="sm_dialstring_choice13579_unicom" continue="true">
      <condition field="destination_number" expression="^90300800[2](\d*[13579])$">
        <action application="set" data="dialstring=sofia/internal/$1@27.115.93.83;fs_path=sip:172.28.50.243;transport=udp"/>
      </condition>
    </extension>
   <!-- this is for even tail number  -->
    <extension name="sm_dialstring_choice24680_mobile" continue="true">
      <condition field="destination_number" expression="^90300800[03](\d*[24680])$">
        <action application="set" data="dialstring=sofia/internal/$1@117.185.44.170;fs_path=sip:172.28.50.244;transport=udp"/>
     </condition>
    </extension>
<!-- 180.153.194.133 to 180.167.67.243    -->
    <extension name="sm_dialstring_choice24680_telcom" continue="true">
      <condition field="destination_number" expression="^90300800[1](\d*[24680])$">
       <action application="set" data="dialstring=sofia/internal/$1@180.167.67.243;fs_path=sip:172.28.50.244;transport=udp"/>
     </condition>
    </extension>
    <extension name="sm_dialstring_choice24680_unicom" continue="true">
      <condition field="destination_number" expression="^90300800[2](\d*[24680])$">
       <action application="set" data="dialstring=sofia/internal/$1@27.115.93.83;fs_path=sip:172.28.50.244;transport=udp"/>
      </condition>
    </extension>


   <extension name="outbound to SBC">
      <condition>
        <action application="set" data="call_timeout=30"/>
        <action application="set" data="hangup_after_bridge=true"/>
        <action application="set" data="continue_on_fail=false"/>
        <action application="set" data="effective_caller_id_number=${caller_id_number}"/>
        <!--<action application="set" data"=outbound_caller_id_number=${caller_id-number}"/>-->

        <action application="info"/>
        <action application="bridge" data="${dialstring}"/>
      </condition>
    </extension>
  </context>
</include>







