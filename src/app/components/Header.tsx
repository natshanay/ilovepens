import Link from "next/link";
import DarkModeSwitch from "./DarkModeSwitch";
import { SignedIn,SignedOut,UserButton } from "@clerk/nextjs";
import React from "react";
export default function page(){
    return (
        <div className="flex justify-between items-center p-3 max-w-6xl mx-auto">
            <ul className="flex gap-4">
                <SignedIn>
                    <UserButton/>
                </SignedIn>
                <SignedOut>
                    
                <li>
                    <Link href='sign-in'>Sign-in</Link>
                </li>
                </SignedOut>
                <li>
                    <Link href='home'>Home</Link>
                </li>
                <li>
                    <Link href='about'>About</Link>
                </li>
            </ul>
            <div className="flex items-center gap-4">
<DarkModeSwitch/>
            <Link href="/" className="flex gap-1 items-center"> 
        <span className="text-2xl font-bold bg-amber-500 py-1 px-2 rounded-lg">imdb</span>
        <span className="text-xl hidden sm:inline">Clone</span>
        </Link>
            </div>
            </div>
    )
}