package com.coreyd97.stepper.util;

import java.io.*;
import java.util.*;


//Shamelessly butchered from: https://stackoverflow.com/questions/7743534/filter-search-and-replace-array-of-bytes-in-an-inputstream/11158499
//Original credit: https://stackoverflow.com/users/276052/aioobe
public class ReplacingInputStream extends FilterInputStream {

    LinkedList<Integer> inQueue = new LinkedList<Integer>();
    LinkedList<Integer> bufferQueue = new LinkedList<Integer>();
    LinkedList<Integer> outQueue = new LinkedList<Integer>();
    final List<Replacement> replacements;

    public ReplacingInputStream(InputStream in,
                                   List<Replacement> replacements) {
        super(in);
        this.replacements = replacements;
    }

    private void readAhead() throws IOException {
        List<Replacement> potentialMatches = new ArrayList<>(replacements);
        do{
            int position = inQueue.size();
            int next = bufferQueue.size() > 0 ? bufferQueue.remove() : super.read(); //Read the next character
            inQueue.offer(next); //And add it to our working list
            if(next == -1) break;
            potentialMatches.removeIf(potential ->
                    //Remove any matches that are too short for our buffer, or logically do not match
                    potential.match.length < inQueue.size() || next != potential.match[position]
            );

            //Create an array of the current state
            byte[] current = new byte[inQueue.size()];
            for (int i = 0; i < inQueue.size(); i++) {
                current[i] = inQueue.get(i).byteValue();
            }
            Optional<Replacement> match = potentialMatches.stream()
                    .filter(potential -> Arrays.equals(potential.match, current)).findFirst();

            if(match.isPresent()){
                inQueue.clear();
                byte[] replacement = match.get().replace;
                for (byte b : replacement) {
                    outQueue.offer((int) b);
                }
                break;
            }
        } while (potentialMatches.size() > 0);

        //No matches, push the next character into our outQueue.
        //Anything left in inQueue unused should be added to bufferQueue
        if(inQueue.size() > 0)
            outQueue.offer(inQueue.removeFirst());
        while (inQueue.size() > 0)
            bufferQueue.offer(inQueue.removeFirst());

        // Work up some look-ahead.
//        while (inQueue.size() < search.length) {
//            int next = super.read();
//            inQueue.offer(next);
//            if (next == -1)
//                break;
//        }

    }

    @Override
    public int read() throws IOException {
        // Next byte already determined.
        if (outQueue.isEmpty()) {
            readAhead();
        }

        return outQueue.remove();
    }

    public static class Replacement {
        public final byte[] match, replace;
        public Replacement(byte[] match, byte[] replace){
            this.match = match;
            this.replace = replace;
        }

        @Override
        public String toString() {
            return "Replacement{" +
                    "match=" + new String(match) +
                    ", replace=" + new String(replace) +
                    '}';
        }
    }
}