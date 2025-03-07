/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import edu.eci.arsw.blacklistvalidator.BlackLisThread;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * 
     * @param ipaddress suspicious host's IP address.
     * @return Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int N) {
        LinkedList<Integer> blackListOcurrences = new LinkedList<>();

        int ocurrencesCount = 0;

        ArrayList<BlackLisThread> blackThread = new ArrayList<BlackLisThread>();

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount = 0;

        @SuppressWarnings("unused")
        ArrayList<BlackLisThread> blackThreads;

        int spaces = skds.getRegisteredServersCount() / N;


        /** Creacion de hilos con sus respectivos parametros */
        for (int i = 0; i < N; i++) {
            if (i < N - 1) {
                blackThread.add(new BlackLisThread((i * spaces), ((i + 1) * spaces) - 1, ipaddress, skds));
            } else if (i == N - 1) {
                blackThread
                        .add(new BlackLisThread((i * spaces), skds.getRegisteredServersCount(), ipaddress, skds));
            }
            blackThread.get(i).start();
        }
        for (BlackLisThread thread : blackThread) {
            /** En caso que este vivo el hilo, continue con la busqueda */
            while (thread.isAlive()) {
                continue;
            }
            ocurrencesCount += thread.ipfoundonblacklist();
            blackListOcurrences.addAll(thread.getBlackListOcurrence());
            checkedListsCount += thread.getcountList();
        }
        if (ocurrencesCount >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}",
                new Object[] { checkedListsCount, skds.getRegisteredServersCount() });

        return blackListOcurrences;
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());


    // Nueva version del metodo CheckHost con el parametro adicional de N hilos 
    //Los N hilos se encargan de optimizar la busqueda

}