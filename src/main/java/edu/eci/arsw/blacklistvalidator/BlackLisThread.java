package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;


/*
 * Esta clase representa el ciclo de vida de un hilo, el cual se va a encargar de hacer la busqueda
 * de un segmento del conjunto de servidores disponibles
 * 
 */

public class BlackLisThread extends Thread{
    private int inicio;
    private int fin;
    private String ip;
    private HostBlacklistsDataSourceFacade skds;
    private int countBlackList;
    private int countList;
    private LinkedList<Integer> blackListOcurrences=new LinkedList<>();
    

    public BlackLisThread(int a, int b, String ip, HostBlacklistsDataSourceFacade blackList){
        this.inicio = a;
        this.fin = b;
        this.ip = ip;
        this.skds = blackList;
    }
    
    @Override
    public void run(){
        for(int num = this.inicio;num<=this.fin;num++){
            this.countList ++;
            if(this.skds.isInBlackListServer(num,this.ip)){
                this.blackListOcurrences.add(num);
                this.countBlackList ++;
            }
        }
    }
    

    public int ipfoundonblacklist(){
        return this.countBlackList;
    }
    

    public LinkedList<Integer> getBlackListOcurrence(){
        return this.blackListOcurrences;
    }
    

    public int getcountList(){
        return this.countList;
    }
    
}