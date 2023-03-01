package cic.cs.unb.ca.jnetpcap;


import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public enum FlowFeature {

    fid("flow_id","FID",false),					//1 this index is for feature not for ordinal
    src_ip("src_ip","SIP",false),				//2
    src_port("src_port","SPT"),					//3
    dst_ip("dst_ip","DIP",false),				//4
    dst_pot("dst_port","DPT"),					//5
    prot("protocol","PROT"),					//6
    tstp("timestamp","TSTP",false),				//7
    fl_dur("flow_duration","DUR"),				//8
    tot_fw_pkt("tot_fwd_pkts","TFwP"),			//9
    tot_bw_pkt("tot_bwd_pkts","TBwP"),			//10
    tot_l_fw_pkt("totlen_fwd_pkts","TLFwP"),		//11
    tot_l_bw_pkt("totlen_bwd_pkts","TLBwP"),		//12
    fw_pkt_l_max("fwd_pkt_len_max","FwPLMA"),		//13
    fw_pkt_l_min("fwd_pkt_len_min","FwPLMI"),		//14
    fw_pkt_l_avg("fwd_pkt_len_mean","FwPLAG"),		//15
    fw_pkt_l_std("fwd_pkt_len_std","FwPLSD"),		//16
    bw_pkt_l_max("bwd_pkt_len_max","BwPLMA"),		//17
    bw_pkt_l_min("bwd_pkt_len_min","BwPLMI"),		//18
    bw_pkt_l_avg("bwd_pkt_len_mean","BwPLAG"),		//19
    bw_pkt_l_std("bwd_pkt_len_std","BwPLSD"),		//20
    fl_byt_s("flow_byts_s","FB/s"),				//21
    fl_pkt_s("flow_pkts_s","FP/s"),				//22
    fl_iat_avg("flow_iat_mean","FLIATAG"),			//23
    fl_iat_std("flow_iat_std","FLIATSD"),			//24
    fl_iat_max("flow_iat_max","FLIATMA"),			//25
    fl_iat_min("flow_iat_min","FLIATMI"),			//26
    fw_iat_tot("fwd_iat_tot","FwIATTO"),			//27
    fw_iat_avg("fwd_iat_mean","FwIATAG"),			//28
    fw_iat_std("fwd_iat_std","FwIATSD"),			//29
    fw_iat_max("fwd_iat_max","FwIATMA"),			//30
    fw_iat_min("fwd_iat_min","FwIATMI"),			//31
    bw_iat_tot("bwd_iat_tot","BwIATTO"),			//32
    bw_iat_avg("bwd_iat_mean","BwIATAG"),			//33
    bw_iat_std("bwd_iat_std","BwIATSD"),			//34
    bw_iat_max("bwd_iat_max","BwIATMA"),			//35
    bw_iat_min("bwd_iat_min","BwIATMI"),			//36
    fw_psh_flag("fwd_psh_flags","FwPSH"),			//37
    bw_psh_flag("bwd_psh_flags","BwPSH"),			//38
    fw_urg_flag("fwd_urg_flags","FwURG"),			//39
    bw_urg_flag("bwd_urg_flags","BwURG"),			//40
    fw_hdr_len("fwd_header_len","FwHL"),			//41
    bw_hdr_len("bwd_header_len","BwHL"),			//42
    fw_pkt_s("fwd_pkts_s","FwP/s"),				//43
    bw_pkt_s("bwd_pkts_s","Bwp/s"),				//44
    pkt_len_min("pkt_len_min","PLMI"),			//45
    pkt_len_max("pkt_len_max","PLMA"),			//46
    pkt_len_avg("pkt_len_mean","PLAG"),			//47
    pkt_len_std("pkt_len_std","PLSD"),			//48
    pkt_len_var("pkt_len_var","PLVA"),		//49
    fin_cnt("fin_flag_cnt","FINCT"),				//50
    syn_cnt("syn_flag_cnt","SYNCT"),				//51
    rst_cnt("rst_flag_cnt","RSTCT"),				//52
    pst_cnt("psh_flag_cnt","PSHCT"),				//53
    ack_cnt("ack_flag_cnt","ACKCT"),				//54
    urg_cnt("urg_flag_cnt","URGCT"),				//55
    CWR_cnt("cwe_flag_count","CWRCT"),				//56 /// cwr cwe
    ece_cnt("ece_flag_cnt","ECECT"),				//57
    down_up_ratio("down_up_ratio","D/URO"),			//58
    pkt_size_avg("pkt_size_avg","PSAG"),			//59
    fw_seg_avg("fwd_seg_size_avg","FwSgAG"),		//60
    bw_seg_avg("bwd_seg_size_avg","BwSgAG"),		//61
    fw_byt_blk_avg("fwd_byts_b_avg","FwB/BAG"),		//63   62 is duplicated with 41,so has been deleted
    fw_pkt_blk_avg("fwd_pkts_b_avg","FwP/BAG"),		//64
    fw_blk_rate_avg("fwd_blk_rate_avg","FwBRAG"),		//65
    bw_byt_blk_avg("bwd_byts_b_avg","BwB/BAG"),		//66
    bw_pkt_blk_avg("bwd_pkts_b_avg","BwP/BAG"),		//67
    bw_blk_rate_avg("bwd_blk_rate_avg","BwBRAG"),		//68
    subfl_fw_pkt("subflow_fwd_pkts","SFFwP"),		//69
    subfl_fw_byt("subflow_fwd_byts","SFFwB"),			//70
    subfl_bw_pkt("subflow_bwd_pkts","SFBwP"),		//71
    subfl_bw_byt("subflow_bwd_byts","SFBwB"),			//72
    fw_win_byt("init_fwd_win_byts","FwWB"),			//73
    bw_win_byt("init_bwd_win_byts","BwWB"),			//74
    Fw_act_pkt("fwd_act_data_pkts","FwAP"),			//75
    fw_seg_min("fwd_seg_size_min","FwSgMI"),			//76
    atv_avg("active_mean","AcAG"),				//77
    atv_std("active_std","AcSD"),				//78
    atv_max("active_max","AcMA"),				//79
    atv_min("active_min","AcMI"),				//80
    idl_avg("idle_mean","IlAG"),				//81
    idl_std("idle_std","IlSD"),					//82
    idl_max("idle_max","IlMA"),					//83
    idl_min("idle_min","IlMI"),					//84
	
	Label("label","LBL",new String[]{""});	//85


	protected static final Logger logger = LoggerFactory.getLogger(FlowFeature.class);
	private static String HEADER;
	private String name;
	private String abbr;
	private boolean isNumeric;
	private String[] values;

    FlowFeature(String name,String abbr,boolean numeric) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = numeric;
    }

	FlowFeature(String name, String abbr) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = true;

    }

	FlowFeature(String name,String abbr,String[] values) {
		this.name = name;
        this.abbr = abbr;
        this.values = values;
        isNumeric = false;
    }

	public String getName() {
		return name;
	}

    public String getAbbr() {
        return abbr;
    }

    public boolean isNumeric(){
        return isNumeric;
    }

	public static FlowFeature getByName(String name) {
		for(FlowFeature feature: FlowFeature.values()) {
			if(feature.getName().equals(name)) {
				return feature;
			}
		}
		return null;
	}
	
	public static String getHeader() {
		
		if(HEADER ==null|| HEADER.length()==0) {
			StringBuilder header = new StringBuilder();
			
			for(FlowFeature feature: FlowFeature.values()) {
				header.append(feature.getName()).append(",");
			}
			header.deleteCharAt(header.length()-1);
			HEADER = header.toString();
		}
		return HEADER;
	}

	public static List<FlowFeature> getFeatureList() {
        List<FlowFeature> features = new ArrayList<>();
        features.add(prot);
        for(int i = fl_dur.ordinal(); i<= idl_min.ordinal(); i++) {
            features.add(FlowFeature.values()[i]);
        }
        return features;
    }

	public static List<FlowFeature> getLengthFeature(){
		List<FlowFeature> features = new ArrayList<>();
		features.add(tot_l_fw_pkt);
		features.add(tot_l_bw_pkt);
		features.add(fl_byt_s);
		features.add(fl_pkt_s);
		features.add(fw_hdr_len);
		features.add(bw_hdr_len);
		features.add(fw_pkt_s);
		features.add(bw_pkt_s);
		features.add(pkt_size_avg);
		features.add(fw_seg_avg);
		features.add(bw_seg_avg);
		return features;
	}


    public static String featureValue2String(FlowFeature feature, String value) {
        String ret = value;

        switch (feature) {
            case prot:
                try {
                    int number  = NumberUtils.createNumber(value).intValue();
                    if (number == 6) {
                        ret = "TCP";

                    } else if (number == 17) {
                        ret = "UDP";

                    } else {
                        ret = "Others";
                    }
                } catch (NumberFormatException e) {
                    logger.info("NumberFormatException {} value is {}",e.getMessage(),value);
                    ret = "Others";
                }
            break;
        }

        return ret;
    }

	@Override
	public String toString() {
		return name;
	}
	
}
