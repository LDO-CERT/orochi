import base64
import gzip
import json
import re

# Standard MITRE Enterprise ATT&CK tactics in kill-chain order
ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
]

TACTIC_METADATA = {
    "Reconnaissance": {"id": "TA0043", "short": "Recon"},
    "Resource Development": {"id": "TA0042", "short": "Res Dev"},
    "Initial Access": {"id": "TA0001", "short": "Init Access"},
    "Execution": {"id": "TA0002", "short": "Execution"},
    "Persistence": {"id": "TA0003", "short": "Persistence"},
    "Privilege Escalation": {"id": "TA0004", "short": "Priv Escalation"},
    "Defense Evasion": {"id": "TA0005", "short": "Def Evasion"},
    "Credential Access": {"id": "TA0006", "short": "Cred Access"},
    "Discovery": {"id": "TA0007", "short": "Discovery"},
    "Lateral Movement": {"id": "TA0008", "short": "Lat Movement"},
    "Collection": {"id": "TA0009", "short": "Collection"},
    "Command And Control": {"id": "TA0011", "short": "C2"},
    "Exfiltration": {"id": "TA0010", "short": "Exfiltration"},
    "Impact": {"id": "TA0040", "short": "Impact"},
}

TACTIC_ALIASES = {
    "stealth": "Defense Evasion",
    "defense impairment": "Defense Evasion",
}

SEVERITY_SCORES = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

SEVERITY_COLORS = {
    "Low": "#28a745",
    "Medium": "#ffc107",
    "High": "#fd7e14",
    "Critical": "#dc3545",
}

_MITRE_DATA = None
_TACTIC_CATALOG = None


def normalize_tactic(tactic_name):
    """Normalize tactic names, mapping aliases like Stealth to Defense Evasion."""
    if not tactic_name:
        return None
    raw_clean = tactic_name.strip()
    alias_matched = TACTIC_ALIASES.get(raw_clean.lower())
    target = alias_matched or raw_clean
    for standard_tactic in ATTACK_TACTICS:
        if standard_tactic.lower() == target.lower():
            return standard_tactic
    return target


def get_tactic_catalog():
    """Return dictionary mapping standard tactic name to list of technique metadata."""
    global _TACTIC_CATALOG
    if _TACTIC_CATALOG is not None:
        return _TACTIC_CATALOG

    data = load_mitre_data()
    catalog = {tactic: [] for tactic in ATTACK_TACTICS}
    for t_id in sorted(data.keys()):
        info = get_technique_info(t_id)
        for tactic in info["tactics"]:
            if tactic in catalog:
                catalog[tactic].append(info)

    _TACTIC_CATALOG = catalog
    return _TACTIC_CATALOG


_EMBEDDED_MITRE_B85 = "ABzY8000000{^vLYjfgAmi;S={;)9<u^vkx3D|Gg*k!uyGGnN!+1TBf5Re9qg{0QQE@oo>``*ly0A=2kGQs^}V{5mogp`l_IQQIh|Mknlu|4lEw&VQrU)H~ViGv-1Km2m{v&aJLM;Nb@59^8Sl5B5H<A0D<5hn33|7rbF1n|dI4uAK5ewh~}h>9)!f6ub;J&eePSa<m<hywQ4|L@=MU+C}j|6<!-<9Ft(Em@ZlSzC)Be-j^k_miy3`WI&;%fq}N@rrc)QqP7jvU|;6N>*>Au<paCfCsgGLi2ZSlie<e*VY*R=QfFpEQ#u$@q8P8rnzwAY_$#FiS-@^*0&;z!eTG})@>3+)k4-Q({rSi`Tq4*{D+SLym}B>Psuykk+?Ygb9d1Ar+nLT>nVtX4f~t0cX^SO^p63ygU5xg9_bGU!g)xeB;^0tdQCEGLS9Ln6KlFlgD_)nBRmuN8`Z-dr!O3WjF8y64bq~_h|Y2iqyr24N+Ocy*1SkE_-fS#*N^BozwahV3JX5#G1<TePUEl$gDCtb|6X{%FfF7rV{jlnulaN1^*j9IAlqMs@l~-US5M)39m$`bku|Ivyoxnmt>EkUft1#xFRbSt-fCw(f5ara{+1KituSA~p~<APc>E9bn+}`L8n1pY!whyYe$4`UhE~`fy^uU9vlW43@lK*7J>Bh|Gn97grHt26)bDldk}n(-djEnDzRIFE^7x}BUk4YhxfgSi!C#50)z$qfr{9zA{=9(K3bM6z7q60a7;ogGth6QUOxvU8rQ0pZdJVR57VM)WSmzzf<#|3lqq$_WsN8IVWkjrT2?q@h(~2MJr-a(wT;tXvHc>j4^&1ReuWh%v*RXh5VckYaxn_1KsGg!{EWA<Ej(-W@GcxOY2>*CzJtR3bZeWpis9}2{t0aztFwfbq9-b*L)Fj-1eT%GHc-iokt`f=ho@TRUZytr;2<+HqgPwuI^=(~A--TP#lWg4e48GsG`?-qB9G=m2BznD`<Ov_cxctd(&{MFoU~6~qLD;j}EV%6XW<j2RByjq_l<*zcm#e<D=g12<E0?n@?mF<Jf%J7VxUt&+-g-e++ZgsSvL-<hXl|u&D4yrm$y-m#U25`OPOo{N=i31Os_N#+K3MoN`We=1mh7nQcnvpY#&7ZqNs~MTx2F+lc)la87+A?SaGRBBhoCQ&t|vVKtHbWQqoK546L1o%!um=II0J9ieUv2Y_NRCQSF*+Ia8F|hb5<l}AGh3Fv+?2qOzL}>B{2(Tz6V)IO<GG3CoN{r>B}J@-H$X0<=6%Bv9^zW@Ao8vsOrQ!x1HAEQ2O98H#YR_(9e#da6=ID*yf3Rzxifxyu#OgWp5Av@F9fI5pKrb!17WPWDf<G6oe5xjCwcg1v|#VN4q2Wz(I0BvY1{d@*1oN7CbhO3J>_2R}*|}woePPzGmJQ?iDqUod&~}0`2L{8n4$G?4Pc|cSj@X{DY;q`?(FuoSj;Y<8M2Hn}i7TEiAe|!1bk-m?a-1n{VOpShFm7MOFa~O$E1paAqUvkp3FH2RsJW$QwM#vsMQZqU(8@B(K&YNh0gp)FcG3Wux_VuDMz4jU2%PzLM2`6_Kk&7H&3#TIC6(4_E}z+%=~sgvaGNO!PAs&lLjNj6j@0m!?{zDs+c^#0-i-#^DG#!QsxmKr#<MNu%CyMY?{X%7nz=gq}jdAU@vy{qcD``TOL*AE!6;MupgF8k|J0FL+OS6RaO(3GdG06>x*eTS&CsF~=VUij3kJj3a>rhx^oDljUcD5uQJkPj3QtG`7AF_+|cs<7ks)VX@uiCP_ozm%eC{lr-9>#?Ydh9_KBH&0#;~SG?J$5YSmHeS~#PN^rdO&+BaJ!B)zl_WWsX&G1-Cw2^XP$fARou$PJX?J`LK*_R5hQ?3&h4zoYp2CFUdVr}2(BPIrZnPpwat6ifqckeWYc}zC?2GAci_vWu9d=f0-G74ALc&fb2itLBMR(&OGbqh`mg3KpUY-J~g*tEe=9e=>#P0OMSK4>xhLpcViV@!yJ@Q+r<N<9A;-ZzM7f*N8eOWU(-ziFS2iInvvOUg7iIF^nO4Dc|knJRY0r$~GY1`BM;{&0UeAed=eOr9q<ANu3rd8+ApJr}`9xP!ZgZT<){qKU&E-p3U_kcPAs7H~!Jt~GTKkPK<(?*2%+3;g8rJ?u6pG>Z|?t@=8Guid~G(5re(vf%}Tx40!+z_J&<5snxEUDKSKUR(WWXe58{I8CD(6*7xqosn$#=#7UQHH7OtPhJbU$#8p862lQ&g|H~p(w<x=77j{_p@=(%GQ6aR+jN-(DY&#aENJv3-;wj`?rho~IPyoy``K29@On~K(}dfoF%Q-hKN!!Z`q$s{ls08uRfV)4<~z+7WcSOOC2;iiMh?6u9pIbx)Jc)(^gIQ+LL=mN=DeTCIt;pPFGskAq$hX}S-q^Q5W!FoAw5ZI)XJI{K?jJ~2n9Xi9SX3Hk6?trJkmVlaC*PO-{9qrRZwWehr_{{cxl^h@elw#VW}AXa`07QT1J6JPUgtz;Q@@i&4SgN5oqVAHpJX1^9v*)!>cU>|N6JkZ7Wrc%OZh0o)uOjKRGjN<WWS^7Cp|#U<_9okt<;8%Wm7vpaFayiLDB=LEf<?_O<00WIld+1it}~)PE&@LB!B6{~bc<U|r=)i+$RKAi2X4=Id$MG3~%R*(Gws*b|F_TH!uV@Kr1dwkEKvMuk3mI8ddfRk)~OizzJU3iZN*1|)M*l<6e}Q@{DxhY<FNfu-=g?mE~={<J;(39=<-Tkd|s6^!K~v5XqquJk0>vv3tAWsU-lNa*HBwsXpkC?rWYC1f46YP}%4G|>y;c(&<wWShLmL*c2S29=CbP9BwbVofFr^X>J#T;{7RToQ^?70C*T-`b*;k(?Dg1lbzD2x!ngY+9EE99sBFUR|NTh5*Vc?u0v(cX*LO2+S8U#Qme9O4>$AVf6=J3OSYm0y|?#b{|Qlb~{pJaHwyoRZTWokZ$)T@DXB>xU18)07E%1nJ28A!D6TSL1v}(f&9>$Ecu{F)B(|I1uh%0V)G0y?iVwQx=^!d(I3h%Rt@N|8Z;!d<Rge818BqTD<4^Tm5U6hT%)@W=!-^R7tHbtcQjDt@wZ#DdTUE%WxwOepM9IPQIgEyR-V!0aI0oY&$7(sRsCK@6slcPLRV-S=pq43N`frif-$9aG_cigdI>O3-(6+;PHQZDV@?TM9pSS;g?fH{r2)n1W9Kx$Z1?A<sgUr3ED4Pw%7*JK&mrh+=Ta%0L{Cnu=ko_`P95?pby0(6J-oV_MC2k`7z?0;%q64FtSSH{*+q}{5$oJo&T#>c-l7Fq^!#y_(ojg+vM^0eSV|)lG)iKM20brn(oCH%iMnGeBzc}ZKAIqFjx!PpdPPEW<+V|w=L=cEB>9LpEU#cI{AR+e5pkR_T_%)NhOt;wIIzH~fWyRs)tuP|{mgSH6LxQsA|{2A{bNb6ho|QiBApvxQgR^l1@`NWkQCwrUbQmFE(gsQyPN+lw8raQ7>9>iVC5M#_&NwWNz<~c<=$EZ*~V<$B%UHS>~+Fvkm<QLT0fb`A((m{Xaw`)d?R|oHHH&E4>vLL)RsV~Z>xAt%*rYly%@PkCLg>&^cn7mDW=3B)t*?auhu2E!uSC0>my5j58sC^!^riEMLk<AJca3&d9fM{&_5dt6&VS!HVNKp4`eMe(n<2+1PvGcx<!&EQL@=<mW&Wo;`CIV4L5Qkq=QD==TRX011U;`0O2asN=<kY-|I-?`S~}>+dZW9VUY!Ko+epgjW>v^$G~x+;9S|B6QZrj85=mtfb}uhgVnBK1QQg2)!n2>m`D1GI%iuPz;XDVz+7fj8ABj`G{nxuA#gkpPHv+T7B#y#h=hcyrKRTj6PYYLxNmx;r#vL^I4uLw#|;ESTTV-ax~0q^vSY8+c39&boH7-DBN}^OT|nRsLlzQNUPzU<<*;Z$4G}#hhYB+Cvr5ulPr7A9leOmzd;!9#3b#gZ3r|jaC_H{nUAeESE7xeDH80^K!AxTH6g+`(gq!&_U~n~36_t|>Zzxw;SCBsO;(<XWVqnWWv<T9&1AF>}+VlX6Oq=flZUT?A@9s29jz-7xtCzbOSeyX1!k{L`Svbx8_#S3O8Boe;_#RY*LbG}~JGG82rC$$8@f+D&|G{co(}hOdEjJ^)fC+?OrO%ne$s#7ew~a7D=<d|ssM?aQ&I{otOyf1DjMtA**6YLy@kso%qx)QJv!vW?yGqs)$f0C*iU<4{i*sOjj%SdP7j%T2V?vVUYnjuq?Rr8eUz=YV8tk;R?+8o5W3J{KK9>a;lsBA=j)B4mlFQ?)bFgauv>rm<I_GITb{ME)2fhWg`LYeqG;ruVV{IO<Zz%<FtTQT;V6_Ea<<UA@NAs;|s7E%|fLf6rukM2t!>^8^q$Y#N8zQ7)Skn6h@^i2k*^*=lWIZA67B+z;JY}xPuFoN!U>pa72m4|p?kfZ&6*BQmOTL^Djn)fJ|MD@28(~2%|5cof)fR>iWjKbPPD6}brf{56QXj)*7U=Xhv0irJc7u^5!HK;E1O5-36r$P4?hjq8;&m58hCm=0S3mfeb>lpQ?tjV~K-3A<d>ig|y8LAY%Tiz%d;>?hDp_syc&bh4E0UL=(OmQ?iD}c?MX3+-)kDNrKY<BeCO=WoRBi>ATO<?MO6vjq$|cs-8%ezeycb`gqac{9cJTpQusAhdbE!%L7#t~XM2*fCSsm2ih)GTs&<Ybnbb_ek7HVrT@N&-(>(S%h{rl5NSe@&Zfgt6@fRG!=(kQJrOMdS4137kDn>T+E?g(Yur=8I}vMaEM*5X5lN`}e?_yUetC(mGW8RYhu=olp4qakp_!>jwy03mXRviW~1S$c8kbnaRpU*=&?H!=8H>v%I@kFzrE<PZ6x7z$jHlvqW=O8q9CA)bRY)`0IR(-U&E0ryqb2$*ldmcsFCrK^~jR52kt@hz1cjKK>d?0SBKRz-Jp&qi3Mjo7;TT#e)>&>Lsn1UYqQ#^eQ#fC<UN(|j@OJe>%AXa1m$M3iM|v8DV7_EC`cRnEXMlgy2!fYdzQT-Sg&D}eF3gtn#h1U@xn)=|K`UDbFv-62IBEc_UV1#u1zTZ<CRcVs53(L*j^^;aMyk4ZNpK`vI;C{5Kh%vV0D67noy$}W)!!Bu|6DhZ>}xKSAG%K7o335cd+H12}+d=J<1K`}8BeK`oFVZjId(9zzGvkg-m>PD)XCg&S0(>P+MrjTVz=<y5X^;I5AguBEN0)8?h>pOunpXs&>NitbtVD!w?N$Mj)(U@|lb0vLSE;u$D-2~MKDn_AE5*3IEP4yJcLoN1aD5&^0nygiCKy>K}9>NBjPiGA7<b{FyxT<YsOO0;mp)A6>fmr!SRH6$@n^m2cO8Y&K*}ybcIgd%}$?d-n`(+lc4?FwGHH(p4Ts&pQfst7Saf~)n;>tNADWIvaI2}NK<YV1{&nbxo@fVb2i@y@@<q=3B^ekkwrgRL3I)!(HeR)YXC8>eCY9Axn2)7h=J()n<sEk*wRED(WL&z)QwcvsF$7*GF2}z)_RTXR%Nuv84HdwMkM@mq}u+ftM?%*Y{t|#!w>z=vOR%MfD7r~w+9FU@Ql^HU?PzG`rG%A%-UxBREV7Ar4U7^~bE79T!<d$!72_g3Nw>alv2MxC?MVgIP^$O`Yd$^r(2@ze=5=If~x0vy6$Dj-|So$fnC5BXD3oQbOIdo4BQfi1HSnHsIwtVy$E=*NnbV|2FnMm1a(EQwH2+n@-5!{ZqtxyI`usZ2mG2rF&oB`_d&*QFe9+)dKbXmpoH?q$Sxs)!VJZMxPVu_oNvY4u)d=&lEj!7Ix+I%^%y@^UvBndYgoeAauQ3wM|QbvWcFs6q6RM@pjoJNuK*OBC9jBUBi7IMDy61bficOUImqjdLkExFV8&ANL~nwo=!SXBbWQzrv?J%1o}2Bc*R9xfw7BQcZT?aJ7&7~WdV@;<Se%YB%D9ni*W`i~-Bikc;1p0MzZ3D7*<z<-Q_{h8ja*OLV!x!wXp!V^J>;=E9iGt3>aM|eIrRRrLDUII&Ea%b4%B@~_O{!_C&gz3vQui&p`{Kj$cDXc?QXsIYQUu6j)kOj%Zd(9)~xYHA%-KSx`GeMG_zKao(gA=^vBZP>Mbw!_B`f+8eO&fV3pJb<#6q|5u1b@47)dJjA#5&g>NR;BlIuj(S=OD@i5WR=Xk~eYaG?u75BUcva<HW#ungx3k7L|?2*d1iqSSiV*cN5Y2r4b)3tx}q4ry^Zzo<AI^?4X%aB5&w&TRM=wC*g|dHa^RS=SLP61&LK%zwP}Ma(4?A|DxDcm8PFj?zXWno<A@cGs(h#!qc(1(WI<Az=?QIOt{P_VI9c@$wO1ZK|6|K9&{UYx113a1glP=|5}o+W??+DthJ?JZ4g6on7?U$pVv!p+VN{A!jB1Ou`q`dI<$|vTvIu;_fx0NzIGd?+Uqz(_`zV!C=sUeDu<*R*Pm_mCqlXAJ4D6?LY91HL?2}!Op-Ju(dK_k+a_+jIiF`Ey5uS!JYmV6;^F$oejpd|nEEHVK%^XLYNoNnL7Q2d*3Q!b0f1zehK00MGc7nycAYL37IS4)6n>b(3emlX7^6h$fCjhIMP%e|z^{FTYlv8s$&DbBB}}BKHSG-gPy|Y$xyv0%*$4frEH+|9d+N{_B$sAznlep!5l<m6q9DB~G<Q7&O_3xgjryB>Lwy)5I``!+9TwhGz2<RIg=yWw*&~DqKmlsPrL1z@^i$}IWyu%qTn<xOSSD&JkBpNJ(WR-HSq$(cIpqG5L~B~YU=&pSz@uj?8krjajRttb1zKFO4ViEO*p?0iRYgTEq0=<)oN~U69Lkq)vn{TQ<m!>U77VM(z?W%hv0p64#1luMPxt#5YrZQtn@ESviL{v>QkL^XGVOsaH6B2YpJWv<(nWc&kt|S#1CQb}2O)OrYZ71G_LSXx*jeL@eg_kvputWQFhp~eC3@8U{vXh$!j*eOy@L2PDlw&gti+8ckyf!Kic7A_M}2#wP_I6-W!)C0{UCsm3EOLkf|y6R%lM|dD!De=+Q`&SaN@goq&-<OYn<=n)iz6F>S|f&x~Ap6TSUW0H(c$>eMmLgby6xD6;L*ap!qk8LZ&f9G0n3;JEtdu;=cyFSyY}8E{;ToAZ^N~K+YvWBG+BS*nam(23GJeaY7?G5n$#+1255#v-aIlTZf21M`~+F@4yH=OvbOOmtV}{6hA`BoN6Mp(eNx+)scDrbTAJY3iuRcZ&%4H8;r*4<))$@wykWg=Td2wN^q`Cu1lmPlB?(WIZ|Sd2oi+RnzJJ<3X38XW7M4Wq?QWyfsI`8vQ_}jg%RjJBwIzf3<FE?m9IK0XO&WXIfmpc5FH{hZ(qGs$A*)YhOG>}N1ZleS-_YNZ&CD>w)C9IY0=+iw@OYL!u1$nu~Iem@OloenfB1!y$5;wA(ACZ#D)NMk6Nd$wWB1|Ok=~&Yc7h{m$bgY>8}*BFrD0D!F1)@&W0o25#=EbM^iA;7xr_C0|_@Yq)E>buH(dHPn;e1c7~RbBSvy%RD@U6>um#?2$~QdePNvDeHcT=N%woPg(R?JdfCuMz%@3up#-mxLCDeFAcAogE1jac(xmTLxx}#}-55UK#z1x1bHzgi*;%<GcswEB+P=&JV)aDo4&f9gF*gk8A{(`rwPcszoSVq$UcaMZfbEJQLzmAEcI1A=-{PdRY1E)yO;-MU{Q8?UUC|y+UG!imQ$kNHt(k}IVU5wJ-9Lv8VWhy^!WbTQh+nED2o<$@WcZ*Y%-B-7Ga4i9ij4`G2}C$@6w`|gM&I!vd_7SNn*xO2@|Ho?jVmqk&EI&Ef4tS?GTs35)4rNL2(j`j$p}_NR3}NuOez_Mf-L@1a46nu=Bia8x{Ww8M}$p>yZRpHWu^RNTB7y_c!kXXU-p$j>!Gva^R<m!wOX=zD0x+;sMN*NOUK8JWB}=Q@>N@0N^T0TMxhn(3dR2H7D5+$uTxK@TM+Y*QH$pbnb<<t-RbO}DA}tg^)&3EdP02{o(%W33Iz3FV^^l-!rM~i-04I~64$k7Bd4Wl>N(q(_e=SLdE{Uc3-Zn&nfO985)Y^E1B%#+2-OSuy(D>YGHcKv!Bhf1O!NG3MmSep2cc)4LJ(}&28HzmKMQ8Tz&#);!pA|V-C4LRhupVpCWKY<lo{GO&T}g6aiJ~ZY>DP#exJ;rFIFPq?PLh)v+f2ytFO!-h%-)VT>#x~{GQXp)O+}egsWqrgjP*G5nnDT?~-_Z3HEHun9Orbu6_i2tHCig8gpT{7?Iis8yk|IW2;v-d9}{$OZ56K9;Y^fb?v7yaZVc_iuXypl>wspR!!S`DPu;mv#x99dh4Fn)Gujyc19z4MhICqm|dF6R{ahEG9AH33=d`8e%%=dqrS3tvYw!LtrT)n<Yg#7r%iL&sG>3KN(HKxacZYbLVtdgd|^me29XG@wNX_$i_7)tu+lrZn?sRy78nS~AUdUAzD+IOMsXSC*GGix1a$k15hp`AhcneQun`crvHA2|Ti@n4T6;Z^+w}Ne)4J~xeDQ)-PRvGg4zQa9H=5=LbM{@jR|skG<(0d&MLU?X{PSi~H-BZOFz~7lE14kl^8EDl{MC30BgfF?VGtpeG<jG&J)%Rl#F=c!bkutAur9lhX*0Fyv!7_PYVv3h&0`*@Z<ExR@9zli^d_TU2WiBL7{<&3rWJ=jExnkTb9MTt`X;={F4vk5BiF2&3WTc4Y+I=1Bci1yTK^+C_PMIDme%-BCe(;ckMvcZE9p~H2Fyqy#o9QSYd-o<M+(IKG_=?ksdK#Bzm|!|lzv*g#6X<&N3ZNjr@(!bd>CoD_vIFZx()aqOabNRhH-b5eI$w8JeEQC5$MSxJQ4?wZzKw+NJ0`Af?IQh(WOSBWu(>Rz#Y4M*qAMZHQ(X=)_;7XuP|4D!oCpi$7?z*hn8%NJ3l{pkR4C^dnkna0QWQbxFGZQhwT}*YAv;U_gLXU)QYV>7R>#dMt!R9peaFR=@o7i8}92WH~^5}m6|hbj<>Vvz-n3Q^*Msn9A5Wz!MM*w**Rkl9a(Y4sA5~DNKU8oV*{m*cejz2^J)CftieI6Ccv^3vA{0yQY-M1oKr;M2iX^=0$DXPSk>)=X><s<(=3VhyM)3cEB1Yzrrg0>Nza&q?h8_&44==!4LCQ_qAhPyKym$+Xi@0CYE_>!0OEuu9~R%PJ8n_Sz$KaYHJ?td>X`}`OXUifP#u@ufR$U*F1?#9TyKmN%iN(nBKD-RNez2tA6u=aFSR<6ciz9z7-2wLg3R8}6Nk-|%Xdot<$W)eQ_W3Sm2$i6p||lE0kYP1aGkr<On!AF<GQM*3RO3rz(_u9g`!&37Gt;rq(a;%*32OA?NG_o;%th-zMK3#>-RcEN)f$Pfts@*KZ^s=X&x3B%TU!(gclffp%EWZ4!N+)-S^LFPFDn@LrgZC#bjogl^|It4+TS$hOX9Bb!4ksc97+ZZcD0MO($5LVBn|qebp8t(FZH)cp5W7)qswPYa5Q*h^2Z<;viy(Cl%5|anyWBk&RRcUI_h@^+-1GFKAz%Md#_FoKBGfgeZ&NgnSrHJ(KLb5?4<$7Gjl;cMa-OraWZu(+`M{So@2ari(8Q&R`+&O|n~df`J_9a#5h`A)!iAx=O|fB`CjiYCAX6y><p=+u%$b7`Fv-J+JIhW22OoZY}=_sUs>^_$~guObRwSSk@J5LwGnfxsQ#RhA0}Y2tC!u)*Pdx9hosyR}nAfXFINHkosc~Z%XP^P5RkA3IF(%*@_(b>MP))+sEm(jy$W4w4A}7Zh}~G<|THkoZeEhzIg|yF91bVwe@7F=)v4{cU>JpUb&;QRw+L=B{o^pChIR?Mt?0y)*_`U&vZrR=^h9n^YEYGM#3Eum!O8hlkpdh8gr#g&QaHwKOT073jAScA+I!z<iL29U&H?nWH~N$@{S<Fx-YhruwB^)IxyxUbwN*#vTC#Tk|af&O=}TsL+Unls`|*JxbQKN1~2Xknebh_P7^xEenMip70Ig#WfsbCJ%onK%YoMTmCfNKQHWVb2|yC)?7=H*oh4|)UYjnmi(2bsWvn{GU?`#C>Sj!xG<;ttmg)#)=9}qaZvC1p4epCv&_iTrpXRI|(WnAGK>DCg2N>72*mm`ZmII88m#(bFeFmn}OhbapG73@I%gkchUq?a4a|MPSOhd08!EnaR7hf*_RQ!L=sO~y9J!GIZ_`SF17RVDVs<Gm+kC?yiNPrgCB}^iscZjG44N59qj%*p(eo&EdY=W{PY3uh;d@WfU9wO!pq)|E4^<3Hr?+HYznw!DFKU2P-D~RMD;v`LCgpVjgx5hP66embo<+L{$zUa(xn}WvMvS31eXLdMph+Dv=Rv7_16d*CC(F{FVC;^Vpp-rhOfid78dFcz=FOVp!(h5CW;LO7myLs0FELhR#>o6Q~$+0Cv@ia`@UB+Wr)Vre+k$fPD0V{;dLpG1wH7QotREyw)tA4TnJKqL~8E)Y(_Z6+|)_6nWOQJB(M^zuR`@wCbp}cO}scoSiRfsDTjHJr9LLyjq?xrv(XuSHp3^Sr&kazG`<nDo>fIT>q!r~!qj$uTZiH0&>Jt6NtvVKkl?9FZlC%26dfjHrCb+TcEKE!=Wk5-;!n#u<rrUuN9*Ks|#A<6VB`hD3IpC|>@qywrG*IA!!KIJfHzV0v0_3&FxazhLA6Oz9bN!kL9t3wWHuvf-}xayelfR}5{dq5a-@NP`OrPDM*5G8YkPsumu1XP}{7$kf$E$0uVQ+WM>>^mr8!WQQMswznOcvHH}EN7fn?FMg8o;L78=zzJ9Nxkr5<fpF$r#jfE*kucs5gm8x%DqWUYgJ>|yD++p(HyUqd*e~!?noutVuVfj9*QEKC%ne<2OmRvC}zvcz?Wqa2%)VipjgwHbpz?wo34VR&~A88=IbO-G!Q6(Fn(LXPL}{?j?lJrs!`Ay>uE+Dj-%gbd0N~sp`$4)<Lnsds6fcT688;}VN}Gs31uCUb9xAQEGcSCvqt!vAP-mFH^i68I~DN3tOyU(Ix$;B+`H<ixSaOtOB_tr9r;cUi=m^CE5G5(WM)2r$`NMDR|%hiRxgt!66B;NU+6JUatd&RzbUYQ(`e$F`w3H!yq@3EKCh3hacZ@zpjO`|>7HeIvmh_JIo4unpl-zE`Gi4L&s7QXn|>ab_eVo2xX~#sC1{J1i(}Bw05bc-woME2?J|Mbv3q?yS?!w5BU)R$15#1-*3B`65jqpHEGen-92GRq;}H6}AfzBxz-k%Pj>X++3FnOo<0Q!y>>$;yZktJICLJcf>)o>&4{sNBlm!?MlD7}A)!Ow!uS)=Cw%zA!&ZqvUT}Nup*zh^dZCr;|9XJF<+{Y`}nfF=Az)n~{+{{TmV=|6#B5uSvEHr-Ju)#maChCi9@(_pL>cOII8mFxwi_o%r3`$HGL9To*7q_?VZN;r3y#uL=JB{B%o>6^^!&Ntro0}j3rH4bdI+%OfO`4yLa`k0Z3p#v>*15D;_&wQP)LP8r*|bHES)#l<NRxd7$563LlouM&`#!BfTYst$p+8^Jj>P(IMB&1`n9+gs=eOMWz7&miDc`nO4R?qZG$F58fK#ACHh;wA&7LqN;BWKCdgZImB#ne)B%=~EwKN^I%p-h972)R%A@XjXqle6#tb*Wq9HjZyr0(w_+HDg$(_=@+L>!z>%>&S`KFZnNLG3=*3etrJiOTGrT>;}&4uKo8n9TL1h=xe-H4E*`<pO+LZuOskeVSQ+dYay_f%kvb(C-#IC?o=PWuwjCkMq8I`i!<#?yQRqpg4?viQhEvbUD7)6>L;eH(9JXM20&u_$|AvI)x0{;^Du3Jir-bu7T>=XA#KUp}gF85IJN?%p~k0syWkbJ;l|%uY@Pg(!mv^Y#RxXG0DUgtib)e(!kQ5)8omJ<ZmQfk}LriY1E}@%SsrNTN+gBH-Gg|<`$a-Y><t62!*@&EEx_SNIF=gb`?>j<!S`f<(+E7Au?3VygS7c+Hfk1Dt0mPNa7FBloUqod|Q)uHWMPhC|dN}I*e(=OnIGXIZLb0$Q5|nbq5;U<}54I?s}U$5-0j>!(~|1j*P|{*kKk_E*RHkAYx1TwrvorLA}A3dsdpwRPSM+EVSTlFbIBi&?Pg~PwC;a1dp-rPkkLG2Z>WA6o8s!5Q?$%>fH!Iun{@}n?H<=)^63DL&%4XO;BurB0#rg($D)m-IDAuhmc?Rn=)Q^T*8I`<UlpWNNy`=nNjO1&`mRohRA)-|N6)|OzY!dAia;1Es3C^^@kR)eI#cI^S8Qb-ue-y9W_o)#S*BzOq!EPb+<r`2<yZhwzrcq{O(&!F4Ar84baBHjJGFrri^mjGucPsQcIW<=}K~t?uL(e!-y#7F^hbp3x>mhT_U%QfVq#viGOs!><e_XAK}$~Sc?~FQ)!&`7Q>U5ZD&EF>W!5_py#merquNXC=<Si6Y#cWv4(SS{X&*V_knl?hmy|3)6;Ed@3ySCSxe1~vrWl)nR+LNi{uIP(dU=H&t9JIr;m3pnk(|}{|678^^siK000"


def load_mitre_data():
    """Load MITRE ATT&CK dataset from embedded compressed dictionary."""
    global _MITRE_DATA
    if _MITRE_DATA is not None:
        return _MITRE_DATA

    try:
        raw_json = gzip.decompress(base64.b85decode(_EMBEDDED_MITRE_B85)).decode("utf-8")
        _MITRE_DATA = json.loads(raw_json)
        return _MITRE_DATA
    except Exception:
        _MITRE_DATA = {}
        return _MITRE_DATA


def parse_technique_ids(raw_text):
    """Extract valid MITRE technique IDs (e.g. T1055 or T1055.001) from input string."""
    if not raw_text:
        return []
    # Match pattern like T1055 or T1055.001 (case-insensitive)
    matches = re.findall(r"\b(T\d{4}(?:\.\d{3})?)\b", str(raw_text), re.IGNORECASE)
    # Deduplicate preserving order and upper-casing
    seen = set()
    result = []
    for m in matches:
        t_id = m.upper()
        if t_id not in seen:
            seen.add(t_id)
            result.append(t_id)
    return result


def get_technique_info(technique_id):
    """Return dictionary with technique metadata."""
    data = load_mitre_data()
    t_id = technique_id.upper()
    if t_id in data:
        raw_tactics = data[t_id].get("tactics", ["General"])
        normalized_tactics = []
        for tac in raw_tactics:
            norm = normalize_tactic(tac)
            if norm and norm not in normalized_tactics:
                normalized_tactics.append(norm)
        return {
            "id": t_id,
            "name": data[t_id].get("name", t_id),
            "tactics": normalized_tactics or ["General"],
            "url": f"https://attack.mitre.org/techniques/{t_id.replace('.', '/')}/",
        }
    return {
        "id": t_id,
        "name": t_id,
        "tactics": ["Uncategorized"],
        "url": f"https://attack.mitre.org/techniques/{t_id.replace('.', '/')}/",
    }


def get_all_technique_choices():
    """Return list of (ID, 'ID - Name') sorted for dropdowns/datalists."""
    data = load_mitre_data()
    items = []
    items.extend({"id": t_id, "label": f"{t_id} - {meta.get('name', '')}"} for t_id, meta in sorted(data.items()))
    return items


def get_case_attack_coverage(findings):
    """
    Given a list or queryset of Finding objects, calculate:
    - Grouping by Tactic
    - Technique occurrences, severities, notes
    - MITRE ATT&CK Matrix columns (all 14 tactics in kill-chain sequence)
    - Overall summary statistics and severity breakdowns
    """
    by_technique = {}
    total_tagged_findings = 0

    for finding in findings:
        tech_ids = parse_technique_ids(finding.mitre_attack_technique)
        if tech_ids:
            total_tagged_findings += 1

        finding_summary = {
            "id": finding.pk,
            "severity": finding.severity,
            "note": (finding.note or "").strip(),
            "created_at": (
                finding.created_at.strftime("%b %d, %Y %H:%M") if getattr(finding, "created_at", None) else ""
            ),
            "evidence_name": (getattr(finding.evidence, "name", "") if getattr(finding, "evidence", None) else ""),
            "evidence_plugin": (getattr(finding.evidence, "plugin", "") if getattr(finding, "evidence", None) else ""),
        }

        for t_id in tech_ids:
            if t_id not in by_technique:
                meta = get_technique_info(t_id)
                by_technique[t_id] = {
                    "id": t_id,
                    "name": meta["name"],
                    "tactics": meta["tactics"],
                    "url": meta["url"],
                    "count": 0,
                    "max_severity": "Low",
                    "max_score": 1,
                    "findings": [],
                    "finding_summaries": [],
                }
            item = by_technique[t_id]
            item["count"] += 1
            item["findings"].append(finding)
            item["finding_summaries"].append(finding_summary)
            score = SEVERITY_SCORES.get(finding.severity, 1)
            if score > item["max_score"]:
                item["max_score"] = score
                item["max_severity"] = finding.severity

    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in by_technique.values():
        item["finding_summaries_json"] = json.dumps(item["finding_summaries"])
        sev = item["max_severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Low"] += 1

    # Group by Tactic
    tactics_map = {tactic: [] for tactic in ATTACK_TACTICS}
    tactics_map["Uncategorized"] = []

    for _, info in sorted(by_technique.items(), key=lambda x: (-x[1]["max_score"], x[0])):
        placed = False
        for tactic in info["tactics"]:
            # Normalize tactic name matching
            matched = False
            for standard_tactic in ATTACK_TACTICS:
                if standard_tactic.lower() == tactic.lower():
                    tactics_map[standard_tactic].append(info)
                    matched = True
                    placed = True
                    break
            if not matched and tactic != "General":
                if tactic not in tactics_map:
                    tactics_map[tactic] = []
                tactics_map[tactic].append(info)
                placed = True
        if not placed:
            tactics_map["Uncategorized"].append(info)

    # Filter out empty tactics for card display
    active_tactics = [{"tactic": name, "techniques": techs} for name, techs in tactics_map.items() if techs]

    # Generate standard 14-column ATT&CK Matrix representation
    catalog = get_tactic_catalog()
    matrix_columns = []
    tactics_covered_count = 0

    for tactic in ATTACK_TACTICS:
        meta = TACTIC_METADATA.get(tactic, {"id": "", "short": tactic})
        detected_in_tactic = list(tactics_map.get(tactic, []))
        has_detections = len(detected_in_tactic) > 0
        if has_detections:
            tactics_covered_count += 1

        detected_in_tactic.sort(key=lambda x: (-x["max_score"], x["id"]))

        max_tactic_score = max((x["max_score"] for x in detected_in_tactic), default=0)
        max_tactic_severity = next((k for k, v in SEVERITY_SCORES.items() if v == max_tactic_score), None)

        detected_ids = {x["id"]: x for x in detected_in_tactic}
        tactic_all = []
        for tech in catalog.get(tactic, []):
            t_id = tech["id"]
            if t_id in detected_ids:
                item = detected_ids[t_id]
                tactic_all.append(
                    {
                        "id": t_id,
                        "name": item["name"],
                        "url": item["url"],
                        "is_detected": True,
                        "count": item["count"],
                        "max_severity": item["max_severity"],
                        "max_score": item["max_score"],
                        "findings": item["findings"],
                        "finding_summaries": item["finding_summaries"],
                        "finding_summaries_json": item.get("finding_summaries_json", "[]"),
                    }
                )
            else:
                tactic_all.append(
                    {
                        "id": t_id,
                        "name": tech["name"],
                        "url": tech["url"],
                        "is_detected": False,
                        "count": 0,
                        "max_severity": None,
                        "max_score": 0,
                        "findings": [],
                        "finding_summaries": [],
                        "finding_summaries_json": "[]",
                    }
                )

        tactic_all.sort(key=lambda x: (not x["is_detected"], -x["max_score"], x["id"]))

        matrix_columns.append(
            {
                "name": tactic,
                "short_name": meta["short"],
                "tactic_id": meta["id"],
                "detected_count": len(detected_in_tactic),
                "total_count": len(catalog.get(tactic, [])),
                "has_detections": has_detections,
                "max_severity": max_tactic_severity,
                "max_score": max_tactic_score,
                "detected_techniques": detected_in_tactic,
                "all_techniques": tactic_all,
            }
        )

    coverage_pct = round((tactics_covered_count / len(ATTACK_TACTICS)) * 100) if ATTACK_TACTICS else 0

    return {
        "techniques": by_technique,
        "active_tactics": active_tactics,
        "unique_techniques_count": len(by_technique),
        "total_tagged_findings": total_tagged_findings,
        "severity_counts": severity_counts,
        "tactics_covered_count": tactics_covered_count,
        "tactics_total_count": len(ATTACK_TACTICS),
        "coverage_percentage": coverage_pct,
        "matrix_columns": matrix_columns,
    }


def generate_navigator_layer(case, findings):
    """
    Build a standard MITRE ATT&CK Navigator Layer (v4.5) JSON dictionary.
    Compatible with https://mitre-attack.github.io/attack-navigator/
    """
    coverage = get_case_attack_coverage(findings)
    technique_entries = []

    for t_id, info in coverage["techniques"].items():
        comments = []
        for f in info["findings"]:
            if note_snip := (f.note or "").strip():
                comments.append(f"[{f.severity}] {note_snip}")
            else:
                comments.append(f"[{f.severity}] Finding #{f.pk}")

        entry = {
            "techniqueID": t_id,
            "score": info["max_score"],
            "comment": "\n\n".join(comments),
            "enabled": True,
            "color": SEVERITY_COLORS.get(info["max_severity"], "#e06666"),
        }
        technique_entries.append(entry)

    return {
        "name": f"{case.name} - ATT&CK Layer",
        "versions": {
            "attack": "15",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"MITRE ATT&CK coverage exported from Orochi Case: {case.name} ({case.status})",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showTechniqueCount": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "gradient": {
            "colors": ["#ffe766", "#ffaf66", "#e06666"],
            "minValue": 1,
            "maxValue": 4,
        },
        "legendItems": [
            {"label": "Low", "color": SEVERITY_COLORS["Low"]},
            {"label": "Medium", "color": SEVERITY_COLORS["Medium"]},
            {"label": "High", "color": SEVERITY_COLORS["High"]},
            {"label": "Critical", "color": SEVERITY_COLORS["Critical"]},
        ],
        "metadata": [
            {"name": "Orochi Case ID", "value": str(case.pk)},
            {"name": "Orochi Case Name", "value": str(case.name)},
            {"name": "Owner", "value": str(case.user.username)},
            {"name": "Techniques Count", "value": str(len(technique_entries))},
        ],
        "techniques": technique_entries,
    }
