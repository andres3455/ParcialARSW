package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;


public class BlackLisThread extends Thread{
    private int inicio;
    private int superior;
    private String host;
    private HostBlacklistsDataSourceFacade skds;
    private int countBlackList;
    private int listCount;
    private LinkedList<Integer> blackListOcurrences=new LinkedList<>();
    
    /**
     * Constructor del hilo de acuerdo a que se le envia la direccion ip a revisar, el intervalo de
     * revision y la lista a revisar
     * @param a
     * @param b
     * @param ip
     * @param blackList 
     */
    public BlackLisThread(int a, int b, String ip, HostBlacklistsDataSourceFacade blackList){
        this.inicio = a;
        this.superior = b;
        this.host = ip;
        this.skds = blackList;
    }
    

    public void run(){
        for(int num = this.inicio;num<=this.superior;num++){
            this.listCount ++;
            if(this.skds.isInBlackListServer(num,this.host)){
                this.blackListOcurrences.add(num);
                this.countBlackList ++;
            }
        }
    }
    
    /**
     * Funcion generada para retornar la cantidad de veces que el host ha sido 
     * encontrado en listas negras
     * @return 
     */
    public int malwareFounded(){
        return this.countBlackList;
    }
    
    /**
     * Retorna la lista de posiciones de las listas negras donde apareció la direccion
     * @return -> linkedList<Integer>
     */
    public LinkedList<Integer> getBlackListOcurrence(){
        return this.blackListOcurrences;
    }
    
    /**
     * Retorna la cantidad de listas que fueron revisadas
     * @return -> cantidad de listas (int)
     */
    public int getListCount(){
        return this.listCount;
    }
    
}